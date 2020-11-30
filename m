Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZP6SL7AKGQELSQOWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E57132C814F
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 10:46:14 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id m3sf7043787qvw.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 01:46:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606729574; cv=pass;
        d=google.com; s=arc-20160816;
        b=I0U45M2tgV4oDa5m/QXerJwcidMjwDLidS7OwaGd+iTK8N/rrKmXM8zTsvGCs3X1gO
         UFboiWitVg9dyC0igNkODPdZ4dusIayR9/QXkqWwywpzqU4a3XjTkjpKprpqKFvcERTC
         tKPZlyqfkqaBWzuYg4HZBatZLfQH05BCKFfGEKkhkw6lBAjfb4UGjTfZ44woTUkQsfeZ
         QUotGEeU1sNQ243YZvAwa5qNsUxymCQHVhj50r7W+zgNF/Gos6Ll3+IbtP5pYJf4L9l1
         dEJC8JIAffkya/hHLzIPcNKnFS8ilva3Yey+KvznC0H+UQ1vKqn3EnXYciB0h9eV6iOu
         TT6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pUguqfKt6mtqTAK1q5DIuGzu1NX821bMJ4inUloN4FU=;
        b=ItGPvA8zhXtuKllh7ELwscx3wNCgFqiTEB090QmudQdDB7xfVXVLQvRCwEZnRIYIef
         CHENgXKDW8hqxkCN1PZMSIJVjTKDekJqHbU6ZvHpH8hzRDr9TpDexMm82tEXjf1nh+9o
         9tblGG+JlHNIwvYM0ocsObRVv+3VteiL/0beWwhT4zBY7z/448gqNW1J8bSh5EAbRAfc
         yKl+etXNSkUrmE6DDCZ1FUI/zNemn6AxiNX9bMiYw64D2B6MOB6nNeaxLqyxyL5SkiCW
         gAVCgPo+SPYJxHndOOLuPXH0UBbb9ui93D+CoBu78hGpqnccygDr+o/9Z0Vq4NZGe7VW
         XkxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=el7JSSV5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pUguqfKt6mtqTAK1q5DIuGzu1NX821bMJ4inUloN4FU=;
        b=Sv/BFIT4+cEhy5V1IlVtsf782mEcoEPXwbOyXg663Wv2OhgzfxBLz2XkdUwPigU3Is
         g+sR+Nh7dmu4XHib2qvCGTndANk7gOURVHtPbS9TiVyq05ePAY0JH6u/JyoXyFFW0/A7
         M6B7b0+EZpOfLFTkQ78NOkmfTYI2y7+Cn9YG9p7GmLwLfs1NptJbURpa6SNtxjm2h3T9
         jvJbMiqB2ludrRi1Wri6RyXWDRWPlwra0KY8Z2zA093ftpk757Mux1uxbTI4qcS7mnLO
         nTTyiiBHM5ROn1wE/JOVzMEpNaImT/HGC4xQDgp+1L0UO7Ozy15l6ePjMiLhLyMTZ4NI
         A7zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pUguqfKt6mtqTAK1q5DIuGzu1NX821bMJ4inUloN4FU=;
        b=YbKM/4oPzupywHGLsmWDf7y3O1+VE0puQikRlM4++6vC3+pkh1DQvZE1O1xY8sArtm
         02qGIFxKlf75kjQtK+Cb9znlalZG7PN01jAdmTLGiVS5XdWnTftRajUwx+RLspSeCHKs
         hdXDZRBWMPRg/n2UztEhic2YBxWGYbu0yVJYRkQLISuxZdh7+t9PBBhX82cCJBIlX2BQ
         wtubdWZRYqXTV01JH8ylGwhENwUD+K1uNAHLleKFehVi8ryYX8dpx2PQC/pb35r9nyXr
         BwawzHyLW7UKOXgLFv/+3i6mumiIXq/ybxGLjcyryYQA2Kkg1wy6i160LCztNipOp7ql
         dxkQ==
X-Gm-Message-State: AOAM532vMTkP0OCus1sEJFuCq2NTRVKRBfv/ty6B1lwEv4LeEay5Gezj
	aUIekspslIg2TuPQL3GP/dk=
X-Google-Smtp-Source: ABdhPJybnC0Q3CkPCeI09eu8tMefuFsVfT5+CAGUG2PEn/k5BjJ2CjuF323OmzoqUwPAi/DmIeGXKw==
X-Received: by 2002:a0c:8e47:: with SMTP id w7mr21233850qvb.55.1606729574048;
        Mon, 30 Nov 2020 01:46:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e29:: with SMTP id d9ls4337861qtw.10.gmail; Mon, 30 Nov
 2020 01:46:13 -0800 (PST)
X-Received: by 2002:ac8:5786:: with SMTP id v6mr21165433qta.268.1606729573561;
        Mon, 30 Nov 2020 01:46:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606729573; cv=none;
        d=google.com; s=arc-20160816;
        b=bVDtoVeMZJMIa4Edsr9YlYAscSwoib/Rp7F9jWZQL1mG2zEkhlaD1Dm1u+cWBWcIzb
         LtkVUELmuAbDKGODJz8otIeuaZyf6ouybNJHRpBd7cI6O/UW0ILuZSJK/5HCJ4Q6lIj+
         VFUA+QijJP2MzuRZeM8pMHVaEK81L5awUhGV+GdpFpaZlhfV5cmYsx1H6QGGyNs2H71k
         PTu84s3uxnSlcmBwMc+tjYf1iavUfQAWRxzwF2bG5Ehl/8z2QMhcdNbgwFlDAuPQnm3R
         hRRoT2gusR/jSjqblfwRZ02Z2P5gBjXZo9f1rt0GtaiAUUPPZPUH+Ku2YKOkLxRyWCZK
         Fclw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=saU5YHYiO2GIaSl/3Zw11N1b7GsRSTY1ffZgL4esVvs=;
        b=j+/8X8sIzu7wieRPbR5llYCAtVCkj8mV3le2blscg+upHGemnAgaKQPt1JYOcHtzvE
         kKAE9UsqXHHm7NBl/iPXdcmesTNikarf7FgF0Ik1Ti/39cyKSyg72p+mYOUTBA4Cnb2S
         G1SS6gwx20zBB9BKH+ThZ97aNtavkOvqmeJ4Vvz8FB/H03BE5beH8D1obJJPXPivbx7C
         8VDdXjon6ga91m6QN/mUl8JyJeTCnXQKcV7vCmFmlLEz8xbHMNipKgrRRAk4Tjt/CtsH
         l2C8gYFX/k+U0WL2hfo8YUPd7GolyjSfPDGUUa+ER1uyLKbhwo6o7/ePq0AMUt0XMU4z
         /7Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=el7JSSV5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id m11si689202qkn.1.2020.11.30.01.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Nov 2020 01:46:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id t18so2239416otk.2
        for <kasan-dev@googlegroups.com>; Mon, 30 Nov 2020 01:46:13 -0800 (PST)
X-Received: by 2002:a9d:7d92:: with SMTP id j18mr16060269otn.17.1606729573128;
 Mon, 30 Nov 2020 01:46:13 -0800 (PST)
MIME-Version: 1.0
References: <35126.1606402815@turing-police>
In-Reply-To: <35126.1606402815@turing-police>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Nov 2020 10:46:01 +0100
Message-ID: <CANpmjNObtKCG3PPdDRrFczHU3wUnybTqp-F2tMx4CB1T+bThwg@mail.gmail.com>
Subject: Re: [PATCH] kasan, mm: fix build issue with asmlinkage
To: =?UTF-8?Q?Valdis_Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=el7JSSV5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Thu, 26 Nov 2020 at 16:00, Valdis Kl=C4=93tnieks <valdis.kletnieks@vt.ed=
u> wrote:
> commit 2df573d2ca4c1ce6ea33cb7849222f771e759211
> Author: Andrey Konovalov <andreyknvl@google.com>
> Date:   Tue Nov 24 16:45:08 2020 +1100
>
>     kasan: shadow declarations only for software modes
>
> introduces a build failure when it removed an include for linux/pgtable.h
> It actually only needs linux/linkage.h
>
> Test builds on both x86_64 and arm build cleanly
>
> Fixes:   2df573d2ca4c ("kasan: shadow declarations only for software mode=
s")
> Signed-off-by: Valdis Kletnieks <valdis.kletnieks@vt.edu>

Reviewed-by: Marco Elver <elver@google.com>

Probably want to add

  Link: https://lore.kernel.org/linux-arm-kernel/24105.1606397102@turing-po=
lice/

for more context, too.

Thanks,
-- Marco



> ---
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 83860aa4e89c..5e0655fb2a6f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -12,6 +12,7 @@ struct task_struct;
>
>  #ifdef CONFIG_KASAN
>
> +#include <linux/linkage.h>
>  #include <asm/kasan.h>
>
>  /* kasan_data struct is used in KUnit tests for KASAN expected failures =
*/
>
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/35126.1606402815%40turing-police.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNObtKCG3PPdDRrFczHU3wUnybTqp-F2tMx4CB1T%2BbThwg%40mail.gmai=
l.com.
