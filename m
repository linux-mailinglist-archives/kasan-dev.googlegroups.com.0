Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGBRW2QMGQEKOGORFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id C1AD693CFB9
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 10:38:53 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6b5de421bc6sf6468296d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 01:38:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721983132; cv=pass;
        d=google.com; s=arc-20160816;
        b=O7XhE13XwOxlzzgjyojtrrohAhRE3COrZtEaqZ20CLdIfD+K3i7JHcDELovLtNFivy
         ctqC2xKovEY01IWfTlR+LNtjcYophsDXoCL73enNIadCA59FQ6JtRFtiJd9FaOM4HI6r
         wB/zFoCAWjsIdfKfcHijbTucEy6trRz39Z7DRI6yhgtTklW4Zxoc9glHdfmAipzfjdMY
         0/ymT8DsgYxEIUFfmU1fNnJ4carVX6q2yeJ+X4KCrWQTGxBL89kV32Z/JC1hECwLqK4z
         kMc17yAmZWUW1ZA8Rv1GPjM+uSWB1HKda+J47pHrDH6+pGtpbN8akHIAEjyXlfmH0mh0
         OU/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uQlBPVSK/FWJipdFRFUPP4tMB4OJBns0HfD6YcslW/c=;
        fh=AGrBDYcFY2r9/d4RgpLC+Fr8GpKViU5VMjnDGnjUEGc=;
        b=jZ2Rje69O9E5oOZyxJv2/Ri7r302CV/6S+q1WPbTcWPR7dZexHZSaTWkG4CRRjMZf0
         jZKFwPJArYLCcWuEcddfQPG1qVV8Idwdjp241goGn+R3i7GrcGucPNb4lIoUWlz3DIJE
         vhg/7EmbEtPuewZOLSvaHmDvP1zcZAWUFz8OPkYAYLZ/OzO4nOQpwih4Ae9/TmNDnpLF
         F3/JanXSry604hZ/pYnHTrRojzZegR3pO7f1spjU3kdENJrc25/X6XxxUuZ2DM6Zwu/K
         3ZDXBVb1vA8VzPaKPfE8Tu8gb2tM2czx2+xUQAbI8AaZPgrLaLP9FLdQ481qcH1xRUQC
         opBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vXSFAWUo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721983132; x=1722587932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uQlBPVSK/FWJipdFRFUPP4tMB4OJBns0HfD6YcslW/c=;
        b=KUn//YHk2evVcfJJ4hWACWMbP4Bx4cu/YYZObSkbHcu1up1neZZZ+YNxsktHsgoL8v
         L9JXZFKR89ZXvbWTqWBrOnU1y9agHDEiXy/Gi9P79rDTWGKxn64KOGdsfopR+R8r4IbY
         PC3J6OUnQzQZvz0q3jDJ0Lmp2XJUJOdrsY1Q+L1i0yMqFHz8kGfKVaaxM9h7YdRMjVrx
         5JyBtNnG6qVBY0xTPgI3E66ZpPfZIaSHJ0IMnS1lKNHAl4la0JVLLrOzoYxMZzKUs3Gb
         aHYvp0/0Cu2sGfURTP5yPjwKTB7hEFzDyrXzkNx64CSjLJTt2SH2WX5kvFdqt8m+eioX
         704g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721983132; x=1722587932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uQlBPVSK/FWJipdFRFUPP4tMB4OJBns0HfD6YcslW/c=;
        b=IPpZ6v6aoCf+lSf/P51rCEtVCmucvq7BvIEiOlkDytGpDa2YBjs+XtFtYHmkm4BSPW
         ZGkjqAMZ7rPcydVbiKSsNZBJlszC9cNxQPKF620b92c2Mq4c7Oz9yWcC2S3C1FEuH1eJ
         /HKOy3dmAuoUMscXqYRnYUccYjPGdthjZXMAcJ65U4S0GEKObioUZ7CGVVP41xCYnXn3
         5bkka1ehZXDpLIDPx9fIci6RN9HY7uTMpqn3h6gH2Jet1UI0d8RFMAR8gdtnxMtQxGnX
         /BqfrcySVGNBoJbPoXNOuHNT1uMIVeA2k9XcD5qx1b3Ee+5LLR0V7YfAdBShX3Vfs5CH
         cK7w==
X-Forwarded-Encrypted: i=2; AJvYcCWRczBToqWzg/BAdsKO4kezrLc9Gr6vo0wx7EogjbduxyJ4f5KhZ4Sibz/5dWqA30z2EOSYGkvpV/OhXPmqrbxB+G3Qwf8AmQ==
X-Gm-Message-State: AOJu0YxbRfuA/ly3vTH2Uj9Swr+Y70Dar5ZQVyYe+DaBwVWkbRVj5bBk
	YyOuKX2YcBxUvPfqAWOZOjomC5g6b5/nkuzPRXYWKHmbx6kE8sJ2
X-Google-Smtp-Source: AGHT+IH5j2N+Aqj/cdQGwbCxtavKncGJ126xyzcl4KwoT/iEO7e0yoPenKzPURc6oyEs+JgbMfzf4g==
X-Received: by 2002:a05:6214:2a88:b0:6b7:9a1c:713b with SMTP id 6a1803df08f44-6bb3cabe953mr58816496d6.35.1721983132600;
        Fri, 26 Jul 2024 01:38:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2e0c:b0:6b0:862d:9779 with SMTP id
 6a1803df08f44-6bb3c07018dls24387576d6.0.-pod-prod-04-us; Fri, 26 Jul 2024
 01:38:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWV0vrc7QOQYBqULHxcaeOX4kvvEKzxTxtQ8V8xKx4ovbuDz8TYcyIXMYl3shbisbE1dYKhtT3HGwvDmmh1TQTK2ub9f3y+QmvXrg==
X-Received: by 2002:ad4:5d45:0:b0:6b7:4712:c878 with SMTP id 6a1803df08f44-6bb3cabf0fdmr84617876d6.41.1721983131905;
        Fri, 26 Jul 2024 01:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721983131; cv=none;
        d=google.com; s=arc-20160816;
        b=IkI/ktp/VTmku8n+HhIyg57BtR1IsTUk39A6tWSWu88PE8Kbl6nS5KyRiiFM82jPlz
         vjSKnxrQj8yxZzjqi+K8wBVoTHZRlYhtuzLBqSaJnvqySFbwO6QG2mOILUY/ATZIfI7N
         ElJ8YErmOW9gONN+JeqGYalinoVvStQrvFOAHQ/bV0fQ74Ns1dZ+sfEaLgdAov92CQ7a
         pV2cF0YHM1ujD5tZyC8pRbdylmN8jxR/b7Zf985ZXE6TDrE77afSPDKWBkHYiXigzlzw
         MDUeZaeGPoyKTiC8tfBaVjTwO4Du8XcVkK8i2iYC+neEgaeV2PnJ9v78IYp49gcH7ZaO
         NyaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pZJmKdKLNSWaXA2BcuG9HwA3qZIS9BmYVk7uzNf6lpA=;
        fh=84g7mXkzEvZJAhHPIZGcTDZu+x4EM+rwIQdMA8c4yc4=;
        b=0Vf8IKarc2QV+S1XSwsHiYcreDcRc88X3Vvh0JB+KiZpJ/FdAdrzofK6XbjiZX28ZK
         9mDTfGH3bJH9JJVUDOnyA8JM8PUSOa6bGgWAWQMgyjkVJZf5clgUe1NrCbAR+AmWUb+p
         sfCyakFH5UkaS1VmnQKCEQcBKHOzNZDu7+Gt7xH0Ctgx+l50ynPlYoic2QR8d8Zwe3fX
         ZNwQtAe4rwL3zB/Bx1eAGLF4j5LzrH4Euz9W1AnbA0fplaazlmHRypC08YRNzAzrq5H0
         80Sy/vdhNbsxg3TNytzRN0uZ5IZRu95ZX9PV8zlZFUCgZz+rjJTd+63JOvSJGwgv7zvc
         AnCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vXSFAWUo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bb3f7e91d7si1101486d6.0.2024.07.26.01.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 01:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a1e0cc1a2514c-825809a4decso168101241.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 01:38:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+Wm47GlECEsLKP6vVP9OqLUZly2oL8u/EUw96w/TMR6gm6m/t+JEjINe9vj3f3pWiHz5Hkm6sbToKAqZCLwgqO3Rec1WgQJBbLA==
X-Received: by 2002:a05:6102:3350:b0:48f:dfb3:f26a with SMTP id
 ada2fe7eead31-493d64737f9mr6876725137.15.1721983131330; Fri, 26 Jul 2024
 01:38:51 -0700 (PDT)
MIME-Version: 1.0
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn> <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
In-Reply-To: <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Jul 2024 10:38:13 +0200
Message-ID: <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Dongliang Mu <dzm91@hust.edu.cn>
Cc: Haoyang Liu <tttturtleruss@hust.edu.cn>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, hust-os-kernel-patches@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vXSFAWUo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as
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

On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
>
>
> On 2024/7/26 01:46, Haoyang Liu wrote:
> > The KTSAN doc has moved to
> > https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
> > Update the url in kcsan.rst accordingly.
> >
> > Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>
> Although the old link is still accessible, I agree to use the newer one.
>
> If this patch is merged, you need to change your Chinese version to
> catch up.
>
> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
>
> > ---
> >   Documentation/dev-tools/kcsan.rst | 3 ++-
> >   1 file changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> > index 02143f060b22..d81c42d1063e 100644
> > --- a/Documentation/dev-tools/kcsan.rst
> > +++ b/Documentation/dev-tools/kcsan.rst
> > @@ -361,7 +361,8 @@ Alternatives Considered
> >   -----------------------
> >
> >   An alternative data race detection approach for the kernel can be found in the
> > -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
> > +`Kernel Thread Sanitizer (KTSAN)
> > +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
> >   KTSAN is a happens-before data race detector, which explicitly establishes the
> >   happens-before order between memory operations, which can then be used to
> >   determine data races as defined in `Data Races`_.

Acked-by: Marco Elver <elver@google.com>

Do you have a tree to take your other patch ("docs/zh_CN: Add
dev-tools/kcsan Chinese translation") through? If so, I would suggest
that you ask that maintainer to take both patches, this and the
Chinese translation patch. (Otherwise, I will queue this patch to be
remembered but it'll be a while until it reaches mainline.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh%2B34Ma8gC1LFCgjtPRsA%40mail.gmail.com.
