Return-Path: <kasan-dev+bncBDW2JDUY5AORBQNJ72VAMGQERZR64LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 910177F65F7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 19:06:58 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-41cdc2cc0b4sf20431331cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 10:06:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700762817; cv=pass;
        d=google.com; s=arc-20160816;
        b=yUS2ejYj6f2JubORVN/wM1orG3pTWzZtU4Rjc5KDY4g7nyz0t1izHmNbOJ8DD/XNKh
         fYRncwtUmB21TnUMsa6M+Ff4ynH79aQbFGhKEQLsxaIIkABCBxZ2FiSB3lG5AGUgaexs
         uzfuvy0JeAQgvlb3Bc0TI0e7m/OSOh3reZjL3P+sYWnYYa6rZfs24vYja8srAMUx9JT+
         qWq+4heyrS7pYCkhnaInKYmoOT/6SE8SQJ/pR9xI330H6a+n9mQ//Wu6XTK2Yn+/Ub3+
         a4PvK5lcDbwPXZHJ/jCPPFXnMISNxZfmbWfiEGMY19CiALdEq7wybk78DmRoS7Bb7eer
         I0Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NIAw+r6O4yDEujTEfx5874dmHCNA1uhDMiIMLw2vBIA=;
        fh=YkVDR0A+vozh5A2Ys2bfc3KlovOzAXgaZ4cuYbKRmSk=;
        b=mqx8EWCOXy7LO4YQTmgzETjfUgM8ixGXgM1Hjq2Y7rFonHPnG+H+leOAG0C+EyP0VG
         HGAip6305UVJ/6bcJboYVjUGT6WVFwRy8GEK+AaljyzT7c6LDB/RO1iaocrxNbdYZaC/
         ykr2obmzFbuk7j/AFJsvNPNBsDqbDhfV/O7PMddOBS5/noxr1FuXFuG4/ZyhfCLHOBeV
         3gvEmyqBo5bx6C9yYUM84uSy9dQ4H62rsU4V1zUbyMrG/DFYhOI4LTal6bj5goAFaEff
         YOUdjyP9hFyrHbPPdr5I6Wi4pMw3gvEairhG6lUhhOOM/NOgf68iMeNNTLSnBWOHkw8K
         4v4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hVHBT9qd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700762817; x=1701367617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NIAw+r6O4yDEujTEfx5874dmHCNA1uhDMiIMLw2vBIA=;
        b=RrcTSyulIyzdh+0IrKandmB/MJ9/FSmSm6CikGo/BXRZkJ4lKNZ+uwMcL1N5GdQ5hZ
         fldqNLn4rtXVBPSKHBgPKItjr5369yt1QiXi2BARpob5iAy5GwfCIQ4dyIDQ+Oxe3oA0
         TGKRqJ5ubcw0F0lAz+HbFJaiyzSfsUzG7XvfUejLzvkfQB92EaKLLH0y5TpdvUdThwzR
         lw8u9nTeZb8XH7v4F07WSY99MfGty5J15WUrEGqh0VR78CSUjMTSGmA+u3Gy/vyfFpg/
         0AdHosHLWoFw0B4D8Jken8NLWC1Wx4+A0oAbnEa+LS94oN/pQTD58NCrJAjGr1mMQBpA
         aBnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700762817; x=1701367617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NIAw+r6O4yDEujTEfx5874dmHCNA1uhDMiIMLw2vBIA=;
        b=iT3aTEXhmCiDy1MEyAcEAgYGk0NHLJCHIv5vPkF79a4ngqJFG+E7HN7mjB6VT9oJGJ
         7krkukD9E87nsK8hVduPe1BR+8tzcdP/hNTXZSCfBr4FUnw1Qjk8/j6OMircpOOd0ay9
         cgZQIDlHmxj3jI7gxD7P4j1TfErnGazsn3attPhdN8skctMrlow2qKnPfGmmBdbPgTVu
         gTRkqjju6fFIDbxErzNrOMTLK631an1FX9NXyBO48zkk7ijB3X1C0jiaITjDSS2qDeev
         NWQ24/JR/O3cS2AO69DM2p3G3IvVg0XJxM7AcdX8TVPIuTIySGmoSvXAxzuGJ3yieIxI
         0rGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700762817; x=1701367617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NIAw+r6O4yDEujTEfx5874dmHCNA1uhDMiIMLw2vBIA=;
        b=i66ROXzwvNyt4MqEOOfbcpwaURNliUuu1jtkANv5tD3bGC5oF7EZTUmr9nsXejTdmf
         SRr8MT+Tf/gwREtghCZin+qOoczy6gRTvjM6N7a0ur2bkxXe2oB7stGz0MHwE52L9u7E
         hM+PPsr7Vl6Uwr7ZcdFefITEyRRkIfJBhRvtnSfIaO1NMBFpo3b/8LlnoFk0z6dqMfxN
         WbJlxRhMINxPzpjOwWAhUBqS/dDOodc5Abj7KZWpcOVq45a7dFRWmqnX9KJd+hCwIO2w
         Ml+1yv94o6c4GgVbVfNwzog0NHs65/xKgHIZxxrEGNhMOuBDfO16HukHb59npjCECmEu
         aZlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyXWQad6ZA8epfPZ3vK1uA4ZOMdldvcCNZC7xQd+MB8zK0k0xNQ
	TRk3dy/YPzZIIOpmzjBCuY0=
X-Google-Smtp-Source: AGHT+IHgRcsaCCjqo6OvcZ3qxwbNhy8aPmRwhjIhGITHVmYzsv9I23xeNyn1Bi7ga2gPOog5G6PUzg==
X-Received: by 2002:ac8:7450:0:b0:417:b53d:a898 with SMTP id h16-20020ac87450000000b00417b53da898mr4206387qtr.9.1700762817604;
        Thu, 23 Nov 2023 10:06:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:58d1:0:b0:423:707e:9eb with SMTP id u17-20020ac858d1000000b00423707e09ebls851074qta.0.-pod-prod-00-us;
 Thu, 23 Nov 2023 10:06:56 -0800 (PST)
X-Received: by 2002:a05:620a:13cd:b0:773:ca5c:4556 with SMTP id g13-20020a05620a13cd00b00773ca5c4556mr4578201qkl.10.1700762816552;
        Thu, 23 Nov 2023 10:06:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700762816; cv=none;
        d=google.com; s=arc-20160816;
        b=Fis6xSO3wy5Jmh3lM7Cxl9u69NGQbIz+5lmCtCSoaC7F+khWe0YtydX+Q36CHu6WIW
         yOH/GCG1QlcNzYR3GUatqETfEkw9oSmhgEtJPb7dQbXDswqvjY4AX9ozCHk22QPoh5dS
         8KHjr2cBomIOIHddloEV4XQuSD9u/o5KdC4R6Ztkb0CTBkcuO9S8LwSLy53lTvTNyGGA
         psnztYNu5foc1RH+2HtR0nrKLsCkOQKGzk1NVpvzCY91V83qxzIOF+sQCWu9l1DgAy5k
         vua1RuMqlDikNJJa5rwTdFuDP9x/f5+ZbII3BqvAcciEBTQr+pB/DV5mYTMNM7CYrVAI
         4R6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NW7KxP8ZBJngylS18OviNYrxyG4ErcVeLDijrBizFds=;
        fh=YkVDR0A+vozh5A2Ys2bfc3KlovOzAXgaZ4cuYbKRmSk=;
        b=xsZyc6m9uYsOz51SBOQF4fNC8BOKBWUBpvwnNEQWbDV++U9juworqN6R8RjEjS04F1
         KYpFSysnLnOGBFtC1i8diJXDxasTiAgCt7ClmhOXuMfO8Dq5RQqvo+cSEapDk4lF8jht
         kgQe3zpGK/oN8JJRCUjFGYqcKyyCp9d2u9UarDuCBPl/X1tT6wSyYLyQ/1SsThX6ziRy
         xBgqQU2hCLLk4ZZdOR0G9TN/1bo31kZEas48hgthQX9oLMoteYKj8fSVIIwQAymwVpNu
         R7kHaf7bRbUoC8pbTD1SAUqcJNPXdgq4qbKfoWJZLDZqC+KFXvNk8wsjspk8IpXVMzMe
         r4Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hVHBT9qd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id dz5-20020a05620a2b8500b0076709fdb678si91458qkb.4.2023.11.23.10.06.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 10:06:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-5bddf66ed63so801564a12.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 10:06:56 -0800 (PST)
X-Received: by 2002:a17:90b:224a:b0:280:299d:4b7e with SMTP id
 hk10-20020a17090b224a00b00280299d4b7emr4710858pjb.19.1700762815638; Thu, 23
 Nov 2023 10:06:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1699297309.git.andreyknvl@google.com> <ZV42s_c3BzCAEwgu@elver.google.com>
In-Reply-To: <ZV42s_c3BzCAEwgu@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 19:06:44 +0100
Message-ID: <CA+fCnZcx-a8EfzQiFtfquXzfCyzL6Fy38o65G_HUbk+Pw+hTpg@mail.gmail.com>
Subject: Re: [PATCH RFC 00/20] kasan: save mempool stack traces
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hVHBT9qd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::534
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Nov 22, 2023 at 6:13=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Mon, Nov 06, 2023 at 09:10PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > This series updates KASAN to save alloc and free stack traces for
> > secondary-level allocators that cache and reuse allocations internally
> > instead of giving them back to the underlying allocator (e.g. mempool).
>
> Nice.

Thanks! :)

> Overall LGTM and the majority of it is cleanups, so I think once the
> stack depot patches are in the mm tree, just send v1 of this series.

Will do, thank you for looking at the patches!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcx-a8EfzQiFtfquXzfCyzL6Fy38o65G_HUbk%2BPw%2BhTpg%40mail.=
gmail.com.
