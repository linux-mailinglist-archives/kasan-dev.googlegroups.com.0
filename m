Return-Path: <kasan-dev+bncBDW2JDUY5AORBAOP7CFAMGQEDOSFHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F55424A0E
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 00:47:30 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id v14-20020a05620a0f0e00b0043355ed67d1sf3357495qkl.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 15:47:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633560449; cv=pass;
        d=google.com; s=arc-20160816;
        b=qdbnv+n4laLYn3OHPIoCSQxSWEXmtLRAvGUMWH8NIJwyezWd4Hs1fUXOK3n453waAx
         5R80tGl15vuMz10w/kr7lVSERbVvEWAnaTs2JXT6RMQ+8KzFHjZ0t1oDkAp10TxJX2ZD
         zu11RPd5LPymkOT3aufFKvXKAOBmlkhNJG4N7Il0E/R16apehfnLoN/fIQqwQUsUZVye
         Xl1ZSKREK5/YXIJvM7WtGvBwkeCRmfhPsaOwDCfz2oJw8Hxz53sAnshmmv4zZ1PTvKap
         KI5Rt9VqwQo4wsT2v/SP+sb/lWNGeDXnqLgt6Q5IT+ZQuvjACb54C3uLE1tM7FHuxY1p
         z/Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=bIsgUktbODG+HvxYwvuUyg4+/A0a8X3w5Mhq0vuZdHg=;
        b=sY4DPx07o298Sqyzvdm8aCLkYRSX3SDpz4vWoLLmZJvaLXSUYlf2VSPl9mtCDso3Xw
         SOeUocia+m9Gx9uaPDEbiARjeoCCzw2ooyy8DbuvFQgPbNGkwYNJLzB2wdl+VRbniHCj
         QXDxXMGwrIczpHEAtE5GJcYzSOHGNmnEzMOIExRsPgP+TKSguxkOjM5Lfu4942fOkTLz
         JViOe0yxJ1/WYjFlPsQLR24oiiJtlK0T8hhvZcILGhrrnFhVZnAFs9HBGepam9uYgmdS
         zksQppA/k9Dj8tEd8cjbe5UAoZnVxbDQeSOKpdyqOR2T73NG3h2bGDn4qjM2Ui0Gy6jF
         +WwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=VWbUl28i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIsgUktbODG+HvxYwvuUyg4+/A0a8X3w5Mhq0vuZdHg=;
        b=cYr9xzC0eBs1+G6vxrRyd7mNUkWTANvIvQFDOS8WWsLJbLHc0YtgEDJgMB7y6Ew23t
         c32pdLanmKnovKIJVsIzqLY7U4FBryroB2YAYalQe59P1lXuyqqIgiOnIXO5ESLZOfdY
         mFJMA8n/9H0LCj6AzalUX7m7DqoaripxY1q3MDgPHv4GMQSdGCqU2MZP4sGHV6eiKK+f
         MVKjKyUFW67dMjOGjmh7MeH8xBcsuRUfCoLTIJ3Cwgw7ZfJ6eWbWAghWnQUWwE2H0hEp
         Gy5FfWtBo90ZWJ4lNF1+QDdr57ZbjP1w5gq5DT9lNl6ZeXM/hyxK/q0bGKL8x3gsFaCl
         oAWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bIsgUktbODG+HvxYwvuUyg4+/A0a8X3w5Mhq0vuZdHg=;
        b=UhAl4akHj+cpjw/sqDnCINSPrMW8/MdMJ3/31MOI4Pm1JJDBjDwpSAhXjrhDBCdcZm
         hDqI++/Y27U6hW/NajFGlTG9GbfDYJCMdbhWy3nDtXuorbXkKs3SYxLyWII+Pzg6+w6L
         q1mrxsFt+Uk+YrU1NN7TGaT0JIRTJgReLfLPC2RkyVe+uu9QXqkpYK0WVor7McOHP+SX
         8LyyCznoj2mEILEp80s7IaOOaDX91RgQOtv0si3iqVjFKJPVSwc5hXiYqol/gj0ls/Ez
         axnsWOPE59AkGE8NAk4n9yGrUQSVe+B/DmVqbn/PTSHcspmXX+1TxfxR0GcNFoSDp064
         LKGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bIsgUktbODG+HvxYwvuUyg4+/A0a8X3w5Mhq0vuZdHg=;
        b=af5AbQG1409xtQ/BExfcwb3ld1KhROCcfWJd6/mtA4trwp1VRhv2SVPC30xzWOHjjY
         64YOv8sDCkzuHu2Gtdj7M5RYnb9LGZtS0dV9qkoOiOF4RxPUZyiZKmkFQ+0NZf96VT4s
         0iMWAgeIHvOdLK26xLtVF9P9oaXv4MejAJNiEGHusr73zAgDvqjKnHxgfoVtX4PcKQkE
         x3SnrCXMXv5lj/u/v98AL6a55/8dehgqI+y14t7ZWpmqonEoilo1zGE/mlcy19iGTpA9
         bxmoQFNMFOOCz1DfKVXQIbPX+lo1QLdG5EeNjlW7mNlvPBeorX1plxeNWWBJC3ua68Mm
         LPLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/hU2i1cGqmu+L/H78rM99MoZ9fcjUNhJyBe6f2c9dg5Cw/6pq
	2Vr9JwiVhHsPyzbEbET+pms=
X-Google-Smtp-Source: ABdhPJz5uYWZnKqPudqFD37MzunuVrluWZ8iJkUUlANRu0RzK2KQChhDzAECZErpwMT/wYWX+oDpfg==
X-Received: by 2002:a0c:b45a:: with SMTP id e26mr692844qvf.59.1633560449706;
        Wed, 06 Oct 2021 15:47:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e84d:: with SMTP id l13ls458053qvo.11.gmail; Wed, 06 Oct
 2021 15:47:29 -0700 (PDT)
X-Received: by 2002:a0c:b44f:: with SMTP id e15mr1012743qvf.22.1633560449360;
        Wed, 06 Oct 2021 15:47:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633560449; cv=none;
        d=google.com; s=arc-20160816;
        b=ru2xw1lh/Hy4lExiRSqGYPLgJtlw4WfaqaQr5zFVYifLxEj2LusBMMwqjX0KIuzDVV
         VCD1AiUx6M/zGStHbLKdgjTAMk8NoNLHjc4GDeVx8wfO19VQGU2i9Q1yQ2JkMUdJovxf
         yMrUujPz5+Meb4h6rDSBnBNDRvbd9CNH2ayVygUEnmbKDElGxRnFudsR1mzLmmh0QVWY
         +IE25BVF9BtXSz6iYiPr3TXBKIrp3zSGeRpW6aglXiyAhUGz53SxAohYwBQNXeusgjP+
         Vq7udHh4yNL9FkTr5j2nN76FEjCTGbMLz+I87Yhhx9SI3QwkyhvnMtolW0EBX29ZgaZy
         DdDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=+muL0MMg2+zY21yDVhBaysqHpXycAhGHwdAWmExSl4o=;
        b=Tq68tbVWX7tqajShPZvImp25mpcIZu3sc71kx28CmBQiYBpl2HFg2KJ6YgQjQH1zyR
         wIBn5B6ePE4npK6LNEd2DY3eks6sY2Kgyio8qGRD7cH2kPAIGn5cuTwLy0xNems0kVX7
         vZRKS2YqQZ1B7sogyvZZWX/WAWhyji8Pz3HD/mzNlCxGRXdOozB9w1Phi1Y6E/ojwQvl
         8I8FmomDGHySkBohvlW3pQemB9/irvkBzzzn5DJ45erEXbnnnZBcgpO6efVkAq/y2oUb
         sqchytPiqdXHqWgEUyIg+uiYu0/d07nMIxSM2sRVWXabS6FQWqJ/6kT1ML3jEdp4xGX4
         zUfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=VWbUl28i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id k16si1375512qkg.7.2021.10.06.15.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 15:47:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id d18so4573786iof.13
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 15:47:29 -0700 (PDT)
X-Received: by 2002:a02:7b01:: with SMTP id q1mr265804jac.121.1633560448927;
 Wed, 06 Oct 2021 15:47:28 -0700 (PDT)
MIME-Version: 1.0
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 7 Oct 2021 00:47:18 +0200
Message-ID: <CA+fCnZfXV7Ctry6P+1xk0TKdG5Ui+AFUcqTsbvRWq=KuzxAXQQ@mail.gmail.com>
Subject: A talk about Hardware Tag-Based KASAN
To: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=VWbUl28i;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
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

Hi,

Here's a talk about the Hardware Tag-Based KASAN mode I gave at the
Linux Security Summit last week:

Slides: https://docs.google.com/presentation/d/1IpICtHR1T3oHka858cx1dSNRu2XcT79-RCRPgzCuiRk/edit?usp=sharing
Video: https://www.youtube.com/watch?v=UwMt0e_dC_Q

In the talk, I introduce the concept of memory tagging, describe Arm
Memory Tagging Extension, and then show how memory tagging is
integrated into the kernel in the form of a new KASAN mode. The talk
will be useful for anyone who is trying to figure out how Hardware
Tag-Based KASAN works.

If you get a chance - check out the video. I tried to move away from
the pattern of recording through a webcam, and instead recorded
outside at a few scenic places. This was my first time shooting an
outdoors video with proper equipment, so it's not perfect, but I hope
it turned out alright :)

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfXV7Ctry6P%2B1xk0TKdG5Ui%2BAFUcqTsbvRWq%3DKuzxAXQQ%40mail.gmail.com.
