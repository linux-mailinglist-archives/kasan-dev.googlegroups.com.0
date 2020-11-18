Return-Path: <kasan-dev+bncBCH2XPOBSAERBMER2P6QKGQELKWO2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A9342B76AC
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 08:09:37 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id w125sf523048oiw.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 23:09:37 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uNIQwccKfSF5sbS4rQYts7G3JP9JO6IerGcoYkDLJZ8=;
        b=fSJzA2zBx46f+liq0xbq3YeTDYr/tC2nTI+NpAX2FsJ9phEuXXOJ2BAumN5HlzL7j6
         FWpFyhD3U+RkcaF+ORy4NPGPt0v3e8eX1i22vZ5yF1L5alZ1xnWX/LiHMjuyv2tkpYpV
         UYMb06r0MO/+SP0tiAciMO0deDvrFyFwSR2JXCla7DKbSPbYc6cPN+Z4o93FOC/I25lP
         F6I/hgKa4uVt0C7PpCgilbNsNnlhJiyfU6W9VEubvu1Hp+UI48gSfYcr0t07NJ5AGuQT
         0zGf6t0SLebqUNK9QjgjWJ/+6V3zbKzKRx1vIgKdOOWjRdxv9oT2XSmsBmPpxzlxkzWZ
         2Jgw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uNIQwccKfSF5sbS4rQYts7G3JP9JO6IerGcoYkDLJZ8=;
        b=qtCwOgZ2B8JccfShlRjJMs1u1pOG0XNnagUsN1LZ942THHmw2Ozz6qb228og6oqREs
         9LDkepOameFG78FkoRoarnGMJdvboWucDH6A7x+rinzkpAUQkw4Sh6reCPpNi513PhkK
         h2teW7n1da4ZK2r7pxGch4IICfvHZlJCbVIwiXShsz4qHikSqEVzi2lQOUGWwohAkUk8
         0ZAdZCfEzLh0p+10NCibT8XYpPxHkEE5avgVr0/RcS+DyM0oT4traaI/V7BxlWqAFi82
         HMRc88nilRPI01FOzCPDnAemMTBxuxu//aEK7ht0Yzp0l/7ekltr+OjqGwmbEaogQr1H
         L/LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uNIQwccKfSF5sbS4rQYts7G3JP9JO6IerGcoYkDLJZ8=;
        b=ujKaIVUrwQWOWC1C39LUVSU87USxlSzQESUo7Armo/cV5wC+zhW2TzjeezCCPUbloC
         1/da9q6Bh5BkLJ1453p9hy0s9p2uVwVjIsaJDydc5ajD8obneYGK5Sdx+2qTqI6wsmHy
         oautjwIzdGxqQ+Af8H3uQvM4HA5YaX3GSZAm+I8bgU2nvZpE02A70Ouh+1r9E9n+R86W
         Fmk8HRHiFhe0ZbwoylZY6jK9kMuQQG8WbkfLi+I0hxzw0XO0yxCYazvDGdXu8+QU8MV/
         6QeQPIERRW6DenTuJgoaMJDW5ejDtttzA/9VhXTnH9AyFr8ZTbbdAyT9HyE3LCAFgEaZ
         DPgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JB30Nu/3uxCgnuLHqn+BXyhCCxzhq/aq5VAJB6pFldYQuxD1c
	vzJmFqHSTG+s/E/3D/p+53Y=
X-Google-Smtp-Source: ABdhPJz+z4let/AZvWufbcGY+ykfosmNoLFP8rV2p325jA7+pEdEs3buUwdNhNJqiikM/jJk8UmWHg==
X-Received: by 2002:a9d:7081:: with SMTP id l1mr5940942otj.139.1605683376197;
        Tue, 17 Nov 2020 23:09:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls4617646oie.2.gmail; Tue, 17 Nov
 2020 23:09:35 -0800 (PST)
X-Received: by 2002:aca:49d5:: with SMTP id w204mr1924766oia.167.1605683375680;
        Tue, 17 Nov 2020 23:09:35 -0800 (PST)
Date: Tue, 17 Nov 2020 23:09:34 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
Subject: Any guidance to port KCSAN to previous Linux Kernel versions?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_676_1932715493.1605683374987"
X-Original-Sender: mudongliangabcd@gmail.com
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

------=_Part_676_1932715493.1605683374987
Content-Type: multipart/alternative; 
	boundary="----=_Part_677_499549059.1605683374987"

------=_Part_677_499549059.1605683374987
Content-Type: text/plain; charset="UTF-8"

Hello all,

I am writing to ask for some guidance to port KCSAN to some LTS kernel 
versions. As KCSAN is already merged into upstream and works well to catch 
some bugs in some kernel trees, it is good idea to port KCSAN to some 
previous Linux Kernel version. On one hand, it is good for bug detection in 
LTS kernel; On the other hand, it is good to diagnose some kernel crashes 
caused by data race.

Thanks in advance.

Dongliang Mu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4a62280-43f5-468b-94c4-fdda826d28d0n%40googlegroups.com.

------=_Part_677_499549059.1605683374987
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello all,<div><br></div><div>I am writing to ask for some guidance to port=
 KCSAN to some LTS kernel versions. As KCSAN is already merged into upstrea=
m and works well to catch some bugs in some kernel trees, it is good idea t=
o port KCSAN to some previous Linux Kernel version. On one hand, it is good=
 for bug detection in LTS kernel; On the other hand, it is good to diagnose=
 some kernel crashes caused by data race.</div><div><br></div><div>Thanks i=
n advance.</div><div><br></div><div>Dongliang Mu</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f4a62280-43f5-468b-94c4-fdda826d28d0n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/f4a62280-43f5-468b-94c4-fdda826d28d0n%40googlegroups.com</a>.<b=
r />

------=_Part_677_499549059.1605683374987--

------=_Part_676_1932715493.1605683374987--
