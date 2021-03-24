Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMO56BAMGQEYJL3FXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24637348514
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 00:11:58 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id da16sf2395438qvb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 16:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616627517; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaoXaJEUzzO2rkyLlTaLLAqZbo8fM3q26tuf7aTgNG5WRuWy5zVYpiHrAc2738qDgG
         wa1IASrf8qIdOB6jLQyfH4LOt+hqh+Jrdoaqj+eIMZrZiwBVyGnKnrMIAoBmH0npYaQS
         tqTWgG+l7U0KdYEet5grK6LimGH7cC+vOy7sPNcj44OCzsLeOY0Zqo3SCGgSHjgdWb8A
         9bzJVz6fNiWZo5P4Kaf5Bk3PTn1sk4KMVeogGw3TOpUnne7sD705rqFxqp3QCXJjCj3I
         JCRvNaDi7f9pS6bKO9NIHU1Ow/wV0HRObLkVeg/8L6l2LeYhzupyWFFE7KML4PZDRQnG
         7w1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qd/pXJ9R+7XVsPE6A53kmOP34aInNS0w7dJmHQpu3rY=;
        b=HryEEv5i+T0iCQwsAXsp3Cd4qgYrB5paYzMB7QpfM3sjbOgbJN5Y2kbZQtE4An2pbN
         pvZetRnW7FL40o6pV3Yx5MKS5u9kl+29372hFUcXBtYoYWjyNhZkxds5zeIQ2MYm93J1
         F9r0q5Rk+rNLQGl92lUlVnwIUa+UN1LDGsGt4n8tKa/FyvZamexmRe2gGQm7PAcp4Mdw
         vLRGzS4Xt6dhJZQT9E34guN05rxfqnPS45dN/wurLIGw3/4+ZudaM1avTF7W5shy63sx
         J6zYKOaG4jvH9475FRy5ibrcXcFsKihgSsPHgncPJQWJEckKj3fuZ6LEMnwC1SR9KuLP
         GeaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XnMWHCrr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qd/pXJ9R+7XVsPE6A53kmOP34aInNS0w7dJmHQpu3rY=;
        b=jUoU1KUZnS/pP7t16KEX1qLQgTVWpioOs4oogYJAf9bqkfScC7T2glsH+w7Vv9a1no
         /UiQ2pyrjI6M2Mn4VJAxudWFD3O91bOp34kPk+E6O+vupXt4zYkgl9U0pNebEyWSIP+t
         Jk/0CAc4eCRSxX4Nz00sBBEmyykNR6SllLTHKZa2Otglka9NB86K646sNxQ5DawVFDlm
         VXGw9YPm2Yhr7ICNoupm35oksqAmbGc0lHj3ye50Wj07EI+p7iAybjErSZaKpE/d5kO7
         y6farfeJXNgDnrdS+nY9GVbWmmIUHf/yEerzk81WJ6NJl11xjaUbZHL+i2aZgwymlJqm
         N9SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qd/pXJ9R+7XVsPE6A53kmOP34aInNS0w7dJmHQpu3rY=;
        b=daoGmQJnNrU2teKuronxy0MVaDWyg7DQpLBtNWMj5BsBlGD4UKHwD1mj9++WFFAQHb
         WgwdXERrwP2z4FI2gwyB/ecVra97DzruGpAUvjp8UJdIATReJ/R66lSyEAp7+5z7N3E7
         38Kpsx2Fz1ww7d4p1wXV9Ob7tWuigETcSf8Oij4n7/5YAuiGClscjqiXDPzOKuJuAi75
         fI6PRYwOtnIGbIIl+OxckvUp3/O05hEU43NMpQhdOSPNaKklBztEtdwkl5acXrQNi82m
         cRst44sGaUwT/UrhJbnUpIJzHvf2BbOv3iA3WbBwLNXYj8dE6sxALl4XSHohtH4J4Ljh
         ChVQ==
X-Gm-Message-State: AOAM5329R4NYcIZeAbTPcjcp30Wbq71ASkuKnXq/e7b6rSTyq86YohBe
	lqrcKERrELyqEKejWOew8Ro=
X-Google-Smtp-Source: ABdhPJy9KLOZ5XgDVVUiICby3ItEP4lUEuQxEvz1jCSj3GufpICHmKbzJJnHgu6YD0wkDHrKr9i63A==
X-Received: by 2002:ac8:5684:: with SMTP id h4mr5270707qta.61.1616627517101;
        Wed, 24 Mar 2021 16:11:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:400e:: with SMTP id h14ls1917161qko.11.gmail; Wed,
 24 Mar 2021 16:11:56 -0700 (PDT)
X-Received: by 2002:a37:aad7:: with SMTP id t206mr5535192qke.139.1616627516683;
        Wed, 24 Mar 2021 16:11:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616627516; cv=none;
        d=google.com; s=arc-20160816;
        b=VnSaMRza1BIc7L5+Tr2vWNU5Ce2TaHxvaqysDcaVllNMRjdVxzYZHUo/7EBJuosyAA
         7qqWv2bEp/NzmPLJjhadCHzOyG2kg8RvU2Z6AfLmyJYaLBvuHUOjFAJRNgnJ01/dfWnp
         kVPe1km0HgB4rKiusYQQqEFS/sfkhDidZy7m6CSpsjfdLKjGPl9m2hJ0KzwaZ+g07H00
         OI5baiZFpX5jiokAPA0dqhy61oN5xtPXCV2fgpuSXIlqBCghgzraL6yjiSh/eJmC1Su5
         0tdSUx/Fso6C8oD0Q5hPJfQ5rY2NXH8v9jlyT1mS5Fy4ZT53g2olqHfewzlnoNJZOZ0j
         JHug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xibY7VsM3uen8eBjYDMbBuXb62rn6BpP560y1L0HSGQ=;
        b=Pg9Lw+Mb/CfY/OYaD/3Gu5ZfQre79dqNmHnrFutdCfzmzL1Zg4C/Fw9k9mg8EFmIOb
         dOgbXcVWbtfAesIBgrQigdi2xL2hbbf7m5K9/lIEN6RVGeoTcdzm0iHksYH/ryye/mQG
         jQjbcG5YnCHAO+fAZ97NV5fJQM7sF8ev0sOsXBuRMJr9zw11Bi8kIijFoUm3QqYSb/8T
         3KOsTxbmT1bE1b9KG1Fq2C5pCRWQ2H4JsA1Kxynyas3eILJae2jpM7xrmDIp8jS8Yv7C
         tIRDRVwc4o6cw1PKbILnyPKDrRv6FjdWm3KbWSEEA/iUdsPUk2g+DUeA1gCAuf3CDR4L
         tE3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XnMWHCrr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id j17si228151qko.3.2021.03.24.16.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 16:11:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id a8so179795oic.11
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 16:11:56 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr3931467oif.121.1616627516008;
 Wed, 24 Mar 2021 16:11:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210323062303.19541-1-tl445047925@gmail.com> <CACT4Y+atQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA+nkTS4eoHg@mail.gmail.com>
 <CANpmjNMFfQs6bV4wrigfcWMwCvA_oMwBxy9gkaD4g+A1sZJ6-Q@mail.gmail.com> <20210324160358.0f36aa1f8ea7098f66fe64bd@linux-foundation.org>
In-Reply-To: <20210324160358.0f36aa1f8ea7098f66fe64bd@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Mar 2021 00:11:44 +0100
Message-ID: <CANpmjNMBUjGL0cVqnAk7cLLHQkaP+YSNhmn+iMQjBo==4z9ryw@mail.gmail.com>
Subject: Re: [PATCH] kernel: kcov: fix a typo in comment
To: Andrew Morton <akpm@linux-foundation.org>
Cc: tl455047 <tl445047925@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XnMWHCrr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Thu, 25 Mar 2021 at 00:04, Andrew Morton <akpm@linux-foundation.org> wrote:
> On Tue, 23 Mar 2021 23:32:57 +0100 Marco Elver <elver@google.com> wrote:
> > On Tue, 23 Mar 2021 at 07:45, 'Dmitry Vyukov' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > > On Tue, Mar 23, 2021 at 7:24 AM tl455047 <tl445047925@gmail.com> wrote:
> > > >
> > > > Fixed a typo in comment.
> > > >
> > > > Signed-off-by: tl455047 <tl445047925@gmail.com>
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > >
> > > +Andrew, linux-mm as KCOV patches are generally merged into mm.
> > >
> > > Thanks for the fix
> >
> > FYI, I believe this code may not be accepted due to this:
> >
> > "[...] It is imperative that all code contributed to the kernel be legitimately
> > free software.  For that reason, code from anonymous (or pseudonymous)
> > contributors will not be accepted."
> >
> > See Documentation/process/1.Intro.rst
>
> Correct.  I let this one pass because the patch is so minor.  But yes,
> a real name would be preferred, please.

I've just seen that the author sent
https://lkml.kernel.org/r/20210324071051.55229-1-tl445047925@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMBUjGL0cVqnAk7cLLHQkaP%2BYSNhmn%2BiMQjBo%3D%3D4z9ryw%40mail.gmail.com.
