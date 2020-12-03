Return-Path: <kasan-dev+bncBCMIZB7QWENRBW42UL7AKGQEXZXFSVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF952CCFF4
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 08:01:49 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id v13sf533213oos.4
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 23:01:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606978908; cv=pass;
        d=google.com; s=arc-20160816;
        b=eNWclUCo7e1NmSD9pjJ5sPwplL31oUfA6cOjTssGh3KIf9G4ruFM9ZbroY1khlUaZ3
         /76YX4Jt+cpY54ecT22JLwx83q7w30MAAG3NF9zfFP9zl2V7mbPR52/yGbuCrBBMCcka
         9Gg+GprFPKOSLuLcySqjN2fRwVbweZIF//jjOOuyPbQPr7bh5iwobgszxB1Grc7x51il
         cvk7otz2JwYsFIMbfuCP/neEgaYhwCZ1dc+TxDAnhr9jAwf0NxKNBjUrZ87mD3hUZb/t
         0YrR4LJtIAkLaswQcCNb7/SPKCKRmI0GLoBO5VOnPzxxIfL31Rk7LySbeWdqALMvglkF
         If1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=27TeivJRBdOrzV6E+UkbU5YR1Y23y/5aLcegkXfJ2kI=;
        b=tUIxpcPfJZeLeVpwsdMjc+42/tr81+sa3wpZh06sFuWfUuntKzX4KgTv+Sao8OagxL
         sbdTpzwgHMjLskGgimKJeY3r46GpykeF9FEveD5PCcMbuQuj5pfg5x+C8TOVYepCKa+u
         2he2AUOSvQBrw6x2Auiv+QE4zQ34Pw0XtW2DgbwAu9Hm3aOYRDZ/9Kl7u4tDKwQPdS3C
         SSao+FUHkXS+dJJnF6/7Ai6mk+TqE8emixMNkjL6JNkoOpdZHoHVduoEklQDTKtsrxtR
         43MUpVmSazo3C5p/BlDDw0fgkVypH8hoH2hb1VtO8dlxSKi0NSgy7xFufqWJY+NmPgSW
         dgPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AEJpqtMI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=27TeivJRBdOrzV6E+UkbU5YR1Y23y/5aLcegkXfJ2kI=;
        b=J8yb9tMHAqTrGOZ3UYq75XAdn/8QmAe+YmKtqbZiQyMIFLkxzsFDYizRu5nwBhRgLH
         Z4Fq1eicnFX/CuyYwhk75a0ScV4bcpw5jSiVghkPw1S+X0Cbx9anJ3RbAJch3Lqyjama
         WwG6U3OFnIcUr2dLlbG6Ywz6FMFg//mHIDeNj+bj/pPzbKl78Gz2VEhduRrLLfxIcvUQ
         eYVoAMRAMO8ag2SWKRv/0sOscrCBuJdR94I1PVo3c1DdWC3dXo3TCPgMivui3FufqAzR
         zuq5ZJB8eJilGcPXTXqETRR4rIYH/0s7Jk06vSbwrjK9JHVnQA9rVGkfeFz12CfLYviq
         qfuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=27TeivJRBdOrzV6E+UkbU5YR1Y23y/5aLcegkXfJ2kI=;
        b=BuKybPzzhKo97S8HPh/XBZQ4md96Z3t/r0nSAQy77FS5S1zW47qZGr0EYxolmRJ8ic
         WdlKPhy8wQi9f12U7EfuaFrGuHCypwtL/3eqOX0QHQTBiB0Ze4j8lxSmbFY9ODjshg34
         5wfQ8OoWEg37bX+2yjd1amtgRvYPciUseJzA9d4vjIpfS4d0kWlepRRvV7+8pgUMd9fd
         kleEHKmnXKbKV5HI912gjv18vlFJKGy7ZJ7WEgpD2qMgmSagzKyLhTTGzrKBHB4v3tIu
         ahi5e+Gn1hkqr8t3RnNUeFsmyzFcRu/0lKzqLYlMW74nQFvnuYQQV8Oj0CchIAMUYO6A
         XHPw==
X-Gm-Message-State: AOAM531nibzQj5Mh5MQ85eBFjgdEs/TO2hbvvAcebnE5ZIAZQhBvgnBl
	EHejeXa8/ZBbj11hsmGnnK0=
X-Google-Smtp-Source: ABdhPJz5f7UyBcOAYw+b/3/M7Daz27Ed14MvF+L+LKlmIsapkiiLh7FnwmzdBeyGSiS7pm7jpshUGA==
X-Received: by 2002:a9d:2664:: with SMTP id a91mr1082305otb.291.1606978907940;
        Wed, 02 Dec 2020 23:01:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c8a:: with SMTP id q132ls1161768oib.0.gmail; Wed, 02
 Dec 2020 23:01:47 -0800 (PST)
X-Received: by 2002:a54:4d8f:: with SMTP id y15mr1020269oix.150.1606978907576;
        Wed, 02 Dec 2020 23:01:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606978907; cv=none;
        d=google.com; s=arc-20160816;
        b=t87Vf5+eYFn+aA5Fxa0/LAe8q0QAAm9vm51f8bcPWyvzsvHVrciOyEGJ+1556UBoDK
         j1iS7QIM8Z7TCcrDGr4LaRtfwz3ALKFfWS8rY7zSusXMEzaXDQJP+fQEohIERhFSKwEJ
         hCMZjssjBZ0z2M/5xDGSdrFQILOdqs4wmXqeD2aE047xcbd/Zs4efqBgYCYigsB/LccS
         cUdAuHeeAkA3+geCx0jN9D2MERUNoQ1vx7DtIpF62pTtRjT+7rkyQW7TjgMsLa+5PCC/
         shf9LcGxDbvE40OqEAjgaahju7BrF34RasfDp6yP60YyaRal5cGABgMRyonRf4cHgtXP
         eyNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pWQ9GYyKSHe1JGWbs3Y1m+BNCxpwEs1X4TY/MrUFeCQ=;
        b=bKXn3BvESXp2h3GePpY/FClbp5zB+A08dmLdX4203/xKPMlr9Gf+EaTRAiw/9K7KIU
         f+Y8GBFJcylrRld5AgEoslZu4LN+AYMMVUbOQsbYxdbrXbFrQIjLP4aotiYdH+WqBvEx
         TmStEKvW+AOLu8awHJte18nTz8YaJUTcBWxffJgCXeVerL6Wjhosum/LtzhChJgQAegk
         htmrvGr0P4nSGGvRu/PR63T6wWI0MI13qh3IFhZjJNCIAZDHy6O6y5xyIfwa4eBxfLzK
         d2k0E5HYPJf2pHJ6CxofetIyVgZReaEtLN/tMuecB1YyBtfx8dRXBee5aE97YUjhxFE1
         fGKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AEJpqtMI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id l192si38448oih.3.2020.12.02.23.01.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 23:01:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id q7so479181qvt.12
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 23:01:47 -0800 (PST)
X-Received: by 2002:ad4:5bad:: with SMTP id 13mr1695026qvq.23.1606978906682;
 Wed, 02 Dec 2020 23:01:46 -0800 (PST)
MIME-Version: 1.0
References: <20201203022148.29754-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20201203022148.29754-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Dec 2020 08:01:35 +0100
Message-ID: <CACT4Y+aQ19fUhDZMeLQeVzdECQhje6CpnH4SVmMQtS_cTPq0zg@mail.gmail.com>
Subject: Re: [PATCH v5 0/4] kasan: add workqueue stack for generic KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AEJpqtMI;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Thu, Dec 3, 2020 at 3:21 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Syzbot reports many UAF issues for workqueue, see [1].
> In some of these access/allocation happened in process_one_work(),
> we see the free stack is useless in KASAN report, it doesn't help
> programmers to solve UAF for workqueue issue.
>
> This patchset improves KASAN reports by making them to have workqueue
> queueing stack. It is useful for programmers to solve use-after-free
> or double-free memory issue.
>
> Generic KASAN also records the last two workqueue stacks and prints
> them in KASAN report. It is only suitable for generic KASAN.
>
> [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> [2]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Walter Wu (4):
> workqueue: kasan: record workqueue stack
> kasan: print workqueue stack
> lib/test_kasan.c: add workqueue test case
> kasan: update documentation for generic kasan
>
> ---
> Changes since v4:
> - Not found timer use case, so that remove timer patch
> - remove a mention of call_rcu() from the kasan_record_aux_stack()
>   Thanks for Dmitry and Alexander suggestion.
>
> Changes since v3:
> - testcases have merge conflict, so that need to
>   be rebased onto the KASAN-KUNIT.
>
> Changes since v2:
> - modify kasan document to be readable,
>   Thanks for Marco suggestion.
>
> Changes since v1:
> - Thanks for Marco and Thomas suggestion.
> - Remove unnecessary code and fix commit log
> - reuse kasan_record_aux_stack() and aux_stack
>   to record timer and workqueue stack.
> - change the aux stack title for common name.
>
> ---
> Documentation/dev-tools/kasan.rst |  5 +++--
> kernel/workqueue.c                |  3 +++
> lib/test_kasan_module.c           | 29 +++++++++++++++++++++++++++++
> mm/kasan/generic.c                |  4 +---
> mm/kasan/report.c                 |  4 ++--
> 5 files changed, 38 insertions(+), 7 deletions(-)


Hi Walter,

Thanks for the update.
The series still looks good to me. I see patches already have my
Reviewed-by, so I will not resend them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaQ19fUhDZMeLQeVzdECQhje6CpnH4SVmMQtS_cTPq0zg%40mail.gmail.com.
