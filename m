Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCVQTODQMGQEUSWG5IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B3823BF891
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Jul 2021 12:48:43 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id t12-20020a1709027fccb02901298eb7c714sf1783854plb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jul 2021 03:48:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625741322; cv=pass;
        d=google.com; s=arc-20160816;
        b=J28Q7xHkCUFrR3pd4Lk39Ol9AITSfNf1psSpmfU8VbOXXgDspKfLqpifQCbTy68jty
         EymZy2nOtOk+wDO6gMIdx2d937dmHVgYiB7L+uYQYZUgYoW/uvJP8H3VKIZFEcaCWqSk
         jQnMylvCjUQyDdHI7RQyQoatSb4q1JB3KM8wm2TtgtaqY63PkBz0VFRiBl58wMSRtRvX
         7CTus72Fu/gZPy/X2NsaJfwJ7OTMT4ShUNYt6t8Kop+HJTwaS/naT2BPTOZHS+VkH9g0
         YlEhaXC8QtHqGqkz0q9tvfHvSSep78H85as5FUxE/y3g1lNhZD0SkLr1eCzx9z5e3OUn
         AUow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0zEbHKkMFZ79m7C18Bh2sL2MCyYl5se2eHP/JOHiZcU=;
        b=WiaFj+Yv4nhtaOR+I2/fe6ShcFW327Mlms1wYtl8GamUH7CYunVnDcov66TfEysw6q
         r6Gb1Z6B/J6XVTAfVfu8BN8cn0owIyFAcG8t0xsgD3VVrqL975y/4PbiGjbFYDyVjGff
         fjswbTwFqN6NdB0Bl4OrzPl1xSOIgXIETHl2sULeyiI2HA5ky4SzuVQkZ2Hm0VmRbnj5
         cHWrt9u5XPx7MQQTB+jBIIlLSP+7pJh3R5zXi/UjefSzOLUyEP+83Ueey8GbksG7paIT
         FpANjHdtOtAmx1GuefgtB07ee7BHWwZ3kLjCCzF4xfbiMbtrKnwq/lNdPnA1dZtAcx5v
         5yFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LLV02j78;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0zEbHKkMFZ79m7C18Bh2sL2MCyYl5se2eHP/JOHiZcU=;
        b=PJ64Gd5WfgG/71gZZ90HQg5Y+CCf0raPfx+IAfw1EEXBTG9TY0Sf8ikD/Ote7TI9KE
         /T7h/AIprjzh+8pnlocRk7cOx/lFAD1MzIcFskaSspPA5N+Ibc4fZksPT8ECtzbqs1ZK
         ilh+vrWW6dq9JS3+/WAkMD8AjIKEopgmw3GxmgeQuadF/4KNIWkko1erVufWD8lsuEzI
         9qBIj5UhQy6uoKbfid9VxfgAyzSSqHEGlWkcZDTdoLLFTMTu7jnXRoDY4Xs3K2Z74jZ4
         OhX2KM5qKBJhXy44PftN6ZhfzMo5J2Lqgoq2UXpDg3e9MTF84hl6BkwuaVZ1JrEml17n
         a2CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0zEbHKkMFZ79m7C18Bh2sL2MCyYl5se2eHP/JOHiZcU=;
        b=Kn8KQq/El1jRCnNBtwHNZsRuXLD2FCVc86PHORVGWzDh8oAqzqyX2V+62+mSM2degS
         NnmNj5Y7LXLKVMUwUIRNVHrM2QSbxGtyxY7x0cAg3s8GacMwpw66S9KDbRDR4BP9Y1K8
         1S6uabQJD1qLyjnJ8tlczZk5W2Cku7MPtk5PkU4dt6c9w1nOfGeDoibsT3QPu+p/LR9c
         BLZGbnWid+HcaHIOoOvVf3V8ZvRaJXcaIikZOCcwjD0Pj/YNADQzOlfUd6qss8Xwxh3D
         0y1LjCRru1yx4KG8TEF/QSGla8H0UPmLBXVI0oaC4jQudulT+fbVXbrazEaOByIGXyuh
         hrlA==
X-Gm-Message-State: AOAM532sXbJRBRI/hekVK1QfjWIrvCGxDoYWpNzEjhfJPV2fPyHYeW4l
	S1i1IFIwp6vjObwzjkWi4js=
X-Google-Smtp-Source: ABdhPJx/LhsU6uoDNhpk5h5U8ZHl7rQ/S+rpPaDXskSndie98tWL/vVMDunKf15wbxnoFWzNIng/Bw==
X-Received: by 2002:a17:902:e890:b029:129:3bb0:37cf with SMTP id w16-20020a170902e890b02901293bb037cfmr24759078plg.68.1625741322098;
        Thu, 08 Jul 2021 03:48:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7d90:: with SMTP id a16ls319626plm.7.gmail; Thu, 08
 Jul 2021 03:48:41 -0700 (PDT)
X-Received: by 2002:a17:90a:f00b:: with SMTP id bt11mr31853783pjb.104.1625741321542;
        Thu, 08 Jul 2021 03:48:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625741321; cv=none;
        d=google.com; s=arc-20160816;
        b=ciOsDEGcZneSHgJpbxMlAgABEOHyxjVONURJ2kYnfm5b+utC/W8xamyC4sxuHHo1kl
         g+pXWIUhuTW+lHugrS+QQRFwTR8YXCJiIZ7CSy5bi+te8nTC7D+p1gzcTGVFpZ8JB0Zj
         qOrKeORPeGeNeIPgqZp+7kKMJd7/qvp3RDaoPxQvyWEyERhUubAoWx3Fw1UTqjSYI78D
         mJzywPoy8rkmcOwhE0+wSNVwy5AY/cgoLwuWPNDGc/cA7wnyTk17rAn6AERIt/7QQzPC
         9zMhduFGyJjT1YYNgbGANp8nS0//T7NOnIhcESGmmBBMm2/E/GswZDis5+S697WbHkVh
         oaew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PWQdEFFi5gT/VdwVZwJU9Ug+X9RRBro8xpy7DghGDeY=;
        b=MvD3SjizeOsK1njTWiqKHRptJtxDlp0V6axT6+jpJF0SidENcuc4xzxHlFuLhbPpTA
         3vOKUn9g0sODEh28x6drALi5W1tU/aDosRf6Wie/EfVkQNelNAHMqjRmZnxrinW7PHRi
         7opIr7awbv2s2r/o1XC60ysgifB3pH8aoTPkD3aeUBp5Q4pnJHHUDFRZPKYO81nKSiLc
         GJqBxwXjYRD8FijuklQJFsuRXI6uS8BvWgGob8nC7sMYBL2oEfJwlTeFZ7sDHDLXI+Bb
         QH5BeAySkAiNjIGSa16nKZU2UGjP+UcWPUDaGJfSpbHbhaaBUETJKDClzh0MNbidokwo
         HIsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LLV02j78;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id t15si98808plr.0.2021.07.08.03.48.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Jul 2021 03:48:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id l17-20020a9d6a910000b029048a51f0bc3cso5379000otq.13
        for <kasan-dev@googlegroups.com>; Thu, 08 Jul 2021 03:48:41 -0700 (PDT)
X-Received: by 2002:a9d:6f10:: with SMTP id n16mr23365601otq.17.1625741320757;
 Thu, 08 Jul 2021 03:48:40 -0700 (PDT)
MIME-Version: 1.0
References: <CAHk0HosPFmeuWoEfAgvTNhzNqqjQ7Hm5=QvmcX67mY5MV-ysNw@mail.gmail.com>
In-Reply-To: <CAHk0HosPFmeuWoEfAgvTNhzNqqjQ7Hm5=QvmcX67mY5MV-ysNw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Jul 2021 12:48:24 +0200
Message-ID: <CANpmjNO4ib8v1w7xfVO8a_zTQn1qztiz9E15XLDhZ+aqCZd40w@mail.gmail.com>
Subject: Re: is KFENCE enabled on ARM now
To: Weizhao Ouyang <o451686892@gmail.com>
Cc: glider@google.com, dvyukov@google.com, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LLV02j78;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

Unfortunately, KFENCE is not on arm32 yet, and we're not aware of any ports.

On Thu, 8 Jul 2021 at 11:57, Weizhao Ouyang <o451686892@gmail.com> wrote:
>
> Hi elver,
>
> Since arm64 introduced  KFENCE has been a time, and I has ported it to our ARM64 product for memory error detecting.
> I wonder is there a ARM architecture implementation now or a RFC patch? I'm thirst for deploying it on an arm32 product.
> Look forward to your reply.
>
> Thanks,
> Weizhao Ouyang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO4ib8v1w7xfVO8a_zTQn1qztiz9E15XLDhZ%2BaqCZd40w%40mail.gmail.com.
