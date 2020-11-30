Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEE4ST7AKGQEFZVUQAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 83C282C879F
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 16:21:54 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id k13sf7485087pfc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 07:21:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606749713; cv=pass;
        d=google.com; s=arc-20160816;
        b=YoxBtui8PnS7L0x80K/oCsG0uIyZqR5QFI3FLvlswkGavlFlP7wPW2wPW1oXZgQJhI
         DI7EhSGlBSQBels3oQFLO4RouzEjb7dqyRhiXsIvOdDWpNdP5cFW1B1K9TcWi4aSV5qW
         MaSoGNv0l2tk0MyHjVAeYEru2SuBgbvLP/dcWywFnoa+CvcgyGI0XFVMzNlfuCskWQl9
         hJ9PrBHiv/2SwGQ31cvWgjkF7PlF078LQTZISPC4EyQR0Z1/RSyaGL/gV16eiTmRaM7m
         716wCpIyV8LNRYyGEjn+FaUUyA5cD0iW0Cw1cFqCPW+/L1BFxdALeHaDbHkSk0pCXOhU
         Pm/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jH9xGzM/DNJnuRH5NAb2xi0WdyRuXJ+/kXtLBoP3MLc=;
        b=jILXiaWXYfqSEzERjhjoPgZjppCh/zOoIEEKWOdp/oRqLXaFoZ7KBMEEpS7OAv7y8/
         G/BCOyLVudAaFS7IWYzex2xjaTBF9+do2sKTp8j+HYgSTSbDIVmiaZu/9wHEQlKb1BvU
         B+34lko5LRd+h7Iqm7sdXarszxHlOakPnJ+brivqOUwjjHmQAt3zcADRyun+460/+92H
         GKLrC8luJfcygHRnnuzjqB+p28aW72CNtqixBdWbhrk99CbQVOJiRP4RLBpyRihYF/zf
         6+hUWqJDvn/EnNlLLsFiZxeiQIfTn/9gUx/VVdsQu+VteV7ReQ8P1fTStH43ygj6zcPk
         rTTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ELCVyhVM;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jH9xGzM/DNJnuRH5NAb2xi0WdyRuXJ+/kXtLBoP3MLc=;
        b=IfFbNLlhOm+khl7ypjkMm0m9+epT2XomLxptOVS4W4BeZ+G2BCx6BAiEU1IQnoMBT4
         99N+MZgGHjT9uVNSp4vVnWqrKUiJic28boXbKGQtINJEYKD6dgreNs8MeNvWq3sSVh4z
         9kbDJSAozs48vd5BMUTvs4vfGPxHzmzk7Kkusw6z+LKHwJs4ojCkW1gRFY+HS9r40vo2
         HMLzcs+skblX/qcSwLKmmPgUb3nQQqQBIoCxSnXWOrjnzydV4SoJfL5etOQnALV8fdGv
         fAvhfdHz5kxtn6wgiFVr92pobQ2X/FcCaJgVjgzl/wXaGhHTzz/+CB/jKFabk9ojK/u7
         90FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jH9xGzM/DNJnuRH5NAb2xi0WdyRuXJ+/kXtLBoP3MLc=;
        b=FAn7q5RqCwnPfPBhymjqPadwHkza+eoA3WG9fHWUtI4ASamch7q7mfpdKiNXxqUavS
         P4ZiX1kbIXOL6cX99JRFINALPT50CMLe0H8f1mYHvps2CIONfdtlq8zZQtSus19hDDO/
         Oc4K0VRP/VFZGC5liVbyqc4ejJbZaTVyf13Bxf8yofjVRGFAazAWOykEbVEswgSYdc68
         feO2HJEkUCcpQKQLo7fg9u+TEr6jMOruUTOtapw+XEj1GnD4mjmGLQc/vzV398DM1nk+
         fDmVTzU9xKUZjYt/BNecQvTZ+Uyy10ey1R3SNSkBoCyCqAvqysHvLXl1jJUxd9CfFOSS
         UiVw==
X-Gm-Message-State: AOAM530AdN+cReCo4Xf20mbcubkRwJ1pBV2Z0lgQtuL/X+E7kuqCbxNL
	mpeIPizJonraGJMUAGMpdIE=
X-Google-Smtp-Source: ABdhPJzAtgxgm1MrX1qq83FDFFa9HbooxGu6W5oqtO0JV1LUyut1/1rFFVv0h7ACBsSEaSiOZFhGMw==
X-Received: by 2002:a17:902:41:b029:d7:dd6e:649b with SMTP id 59-20020a1709020041b02900d7dd6e649bmr19290976pla.74.1606749713057;
        Mon, 30 Nov 2020 07:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b82:: with SMTP id y2ls6019044plp.5.gmail; Mon, 30
 Nov 2020 07:21:52 -0800 (PST)
X-Received: by 2002:a17:90b:a53:: with SMTP id gw19mr10427314pjb.216.1606749712575;
        Mon, 30 Nov 2020 07:21:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606749712; cv=none;
        d=google.com; s=arc-20160816;
        b=v8YwYKUHUy9GqooCh+DB0NCbCSLXxYeX7Q9WPANRQG0AoGFe10ikyLtAMbO63VN7WF
         XS3wLU7b2iXgiVMhfDkz+uaybe0I08Hv1O7dAaO6faiC2AXKdHmNStMaOkAfZNP0Id8J
         shKip9rsSxmu/2f3v0AWjfj1Mf7yFPapRBk/vFfajo5t7OFxPjMd51V04srynTdDTKJj
         NoWIgH961yTvghmFP2bn4M5E1Uq6sAK/+JoWw0jZg9a+FKAdAMQTVnYoB13eWcrCUCmn
         CyCROJJgWDY/mzt23JnAHxiBZ7fAxbloMmIZor8g33IvaACT4y55hy1tBaJzlFiAKJoU
         xMBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m8hVr8GdgFLwTXrn/Iee2wivZsDYaXNlqxZl8NLWHAA=;
        b=QAz3+LhL+T0R0ujO4VC0T7TH9Cdy/NvCavOabCvxEy4y3jW99tqhSS+UMMPFeGQqgx
         HITYYgSZdcJmXTJGbQzGUM+wapAYlno+vYi3Att7OQxsSyKjESdeSWECB/ol5Z6RXJol
         ZZge5652Sd7RrrIleI7ImLM7tgaxzZBgkhuSY9c60z+/5dhpstjgi0xGo5fEFc/oREQs
         MPiqMmOWViVcMlb+OPNhMkjWh/IBkKTHJZnZE9cubvoWZ8G6C/6WPeeJQjXT/zJ269LB
         6R4LtIofvZxBeGh2erQkOWrpZDrsqAGFPs5C3wKUt8U3WtDISze4T7vwrM/qK3hx+DND
         NFhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ELCVyhVM;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id u133si943101pfc.0.2020.11.30.07.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Nov 2020 07:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id g18so100674pgk.1
        for <kasan-dev@googlegroups.com>; Mon, 30 Nov 2020 07:21:52 -0800 (PST)
X-Received: by 2002:a63:f20:: with SMTP id e32mr17954621pgl.130.1606749712100;
 Mon, 30 Nov 2020 07:21:52 -0800 (PST)
MIME-Version: 1.0
References: <35126.1606402815@turing-police> <CANpmjNObtKCG3PPdDRrFczHU3wUnybTqp-F2tMx4CB1T+bThwg@mail.gmail.com>
In-Reply-To: <CANpmjNObtKCG3PPdDRrFczHU3wUnybTqp-F2tMx4CB1T+bThwg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Nov 2020 16:21:41 +0100
Message-ID: <CAAeHK+xn=aOq7vU0FKNDj8txU6y05g-5=mnkcn3RsWJsoPCfFg@mail.gmail.com>
Subject: Re: [PATCH] kasan, mm: fix build issue with asmlinkage
To: =?UTF-8?Q?Valdis_Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Russell King - ARM Linux admin <linux@armlinux.org.uk>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ELCVyhVM;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Nov 30, 2020 at 10:46 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 26 Nov 2020 at 16:00, Valdis Kl=C4=93tnieks <valdis.kletnieks@vt.=
edu> wrote:
> > commit 2df573d2ca4c1ce6ea33cb7849222f771e759211
> > Author: Andrey Konovalov <andreyknvl@google.com>
> > Date:   Tue Nov 24 16:45:08 2020 +1100
> >
> >     kasan: shadow declarations only for software modes
> >
> > introduces a build failure when it removed an include for linux/pgtable=
.h
> > It actually only needs linux/linkage.h
> >
> > Test builds on both x86_64 and arm build cleanly
> >
> > Fixes:   2df573d2ca4c ("kasan: shadow declarations only for software mo=
des")
> > Signed-off-by: Valdis Kletnieks <valdis.kletnieks@vt.edu>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Probably want to add
>
>   Link: https://lore.kernel.org/linux-arm-kernel/24105.1606397102@turing-=
police/
>
> for more context, too.

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thank you, Valdis!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bxn%3DaOq7vU0FKNDj8txU6y05g-5%3Dmnkcn3RsWJsoPCfFg%40mail.=
gmail.com.
