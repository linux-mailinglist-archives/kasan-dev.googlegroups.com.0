Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG74UL7AKGQEXA7HH7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D942CD372
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 11:29:48 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id l69sf423052vkl.4
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 02:29:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606991387; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypOcj4R+mJ7DXWiJxggKtgTQc4U7hU3dwiLF2gDyhWTFk/kdzFZIdo+36QCD47zNyK
         oOSolkA5O7sASXSctDuYZvteRta0IYKIO9doCqMSMRhVeLSkd8wBGfeE1Q3UJUwfVKiY
         xDhlMnWDU/Urv7ifve7VbQeuYOf4z/TaiiG8ghE+hDIFJLXRyu5Q06mKueM8rpjBo7Gf
         /R0VnIjeq9DqLFyvcMmKhJbiAgRRpdlYfpvvp3SJVlN6nxlToaFZKNos1DZj6IkZNJF8
         TtVv7pR29nhEisr3LdZ+O/Ngy0mrjfEYfwzkh7lnE8ATCTJfCUysEGMg1XGg2+nrxH+P
         W7Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3NIAbkpeGeCEow3FAK2aSE8qgKDpEfagARTtOldQ/DM=;
        b=L6+wv5at89myCKlXkL8WdcUk+gw8O1iFQpU5JSynyNXHwKiwfcq46d6zvroXya8O4z
         QodbNBaZsjQwioGX+2YliROuNS46OM3xTkFruvPWruBBAdIXngtxN6WV6WUhavxQzySL
         e4O3XfBoypAiX3Zut5jbXD/hDC4zpU1rUstYr1M3lW6Gaa2MOkNprfAAS3cZ8OuUJQfC
         9k/9IDtEbNfms0R0dI4u5v6iA5654TwOxO7gF8pH+oZqjpgxIz2F1+jx5dyUqfk0fHfa
         7RYjjEtFIYC8IaGosrWAZ9rEX+LyDS3IzCAk6d8BJF9yR/PHuWkUA2LeEi3612hDVWsx
         Z2WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sNAUb/6E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3NIAbkpeGeCEow3FAK2aSE8qgKDpEfagARTtOldQ/DM=;
        b=e35mcK5ffBPlb/PDJgf5tVjVwriTi1bSgkhYcPfx9VV3Xdgp44AbqUmuiDRt4IK/Ic
         /OiR6nqubfXZ8/0GnlE6OR9fdc2Ko7JWxopzOS/1tGth5+Fi8704lVFJvfWoACoCl1K5
         jKsSynso2vm8KZkLE9uA+9V1i7MN8+5GdKwgnLGprWcDo9t+oJ6jcXTKc5tTOKkaJl8L
         J3nTGR29bP20qVlfJYPAPrJYMSz14cbi6lVLWuodcOtXpLwiX+OEGggVAJPHa+MQ60d0
         MZBftCrSnNs25gQ+Lms5VF8RbtrwDi38AB5WZxcSje7UPPjruZi0AVus492IcmnkARMi
         oHSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3NIAbkpeGeCEow3FAK2aSE8qgKDpEfagARTtOldQ/DM=;
        b=Hrq5fQQIO3g376YUGcWZ1BdDUXrpjsTQKHYwsVROqZk0CQfA/xuA5m35YW0IhwjN4A
         iMHH4YcJdRRFFE32p9v3FSUwnIX/8MLwesh5uOB4OFy+uum2XjVN1esPKAUY33P2S8EA
         qyrDu5JQHiKiGDZTyWa09sfCHJnMEyrnC82c+ILkoUpHqwP4sYN13HlulcU3nAToJlwZ
         r1gZRHxCRA+/D9BXTJuBszPnqhvbnVCIZZMhVsp+lS0eh83Qh0y2v0bpnqg8Bh/I8e/r
         KwuT0W9p0VeHFVabt5WKw2/pRJYq5LwucclBb6Z8tmCtPrqjGlycCwk9JEzYs8KTxzFJ
         yCKg==
X-Gm-Message-State: AOAM5313zr6Q7RaAx0mIkd672YPlPXFYX1ROZqsiYHj9yrqbh6Iawjft
	W41HTRr6ZBjdwAy1X9/yadA=
X-Google-Smtp-Source: ABdhPJwbaigb+HRl8jHlhtSY2UCvjwzCDuxJxCMF4areiJZmGPk33OX8UAQfDq/GIzlKn0PS4ANUCQ==
X-Received: by 2002:a1f:9e89:: with SMTP id h131mr1133248vke.7.1606991387138;
        Thu, 03 Dec 2020 02:29:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls685937vsm.3.gmail; Thu, 03 Dec
 2020 02:29:46 -0800 (PST)
X-Received: by 2002:a05:6102:2413:: with SMTP id j19mr250012vsi.17.1606991386603;
        Thu, 03 Dec 2020 02:29:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606991386; cv=none;
        d=google.com; s=arc-20160816;
        b=mRULHnf+8gmeA3ZYtYSTgekxdQhTxuGgiN2FULPQ0oIx0paxvJ9NyFx95baYUqL75A
         o8qR8HFE3v0uQEWgueKZiGcpUzRhiojruiVsC8cbKEfaMWKr2maW13Xk00sg2iSORrfo
         F1xcyRDKJMNUL/LhQjn1qJkKTJC2Jb/eJsfz04cBnQ92lZGyxCPotviP2WmHnJkZ8bcq
         ++WAoA/agaKsDKgfYNhzb8aasA9Jwkcp+OmOqTUMKVGTsVo2BNMM2snPVRPyD1ptNTHV
         c5WpCuBTRF00sE+uwC2QwdPdNuRTuN/MBha6w0VR4zNRrkNBweD0AxHssJnM3ksR/JCN
         5dDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dD/UF3nKA/vHAeqLilY0XbqwU9Dd3XarhmvDlCA55tM=;
        b=WMfC3qCt9Y03CVSmDY1uMCr2jKIELoFeJ7fjMeg5Ut3MK661aisyEPr16EGiL8vMxA
         DXy6sW/VckQa+YHd0FRJskcFIM+alSScBGqKjR3/k5eragquHt3DcbZ9ZQQKAuQmDsWK
         K6QkArqAGYVuVm3wWbv55c95siZCs9J5RRlNDn05foKilCPFVHAGCBZfXxnQ8A1MguuJ
         U9Tqfouz/xsZY4G3eiZ07Q3zFndK8928Ju84xIIOH85oE67qrqq2Dnf/tf87OhU3QwgC
         b5biCqV2NVFD4SIondlbYzjAznrS64wj0KeixN8ujEB25P/wik+waZW7lcGUmFKht/eu
         9CHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sNAUb/6E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id a16si68446uas.1.2020.12.03.02.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 02:29:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id j12so1258252ota.7
        for <kasan-dev@googlegroups.com>; Thu, 03 Dec 2020 02:29:46 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr1563625otn.233.1606991385992;
 Thu, 03 Dec 2020 02:29:45 -0800 (PST)
MIME-Version: 1.0
References: <20201203022748.30681-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20201203022748.30681-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Dec 2020 11:29:34 +0100
Message-ID: <CANpmjNNdaiN=J0TU_AjAoH=ECNC8dJWS8HTvJs9nxBkJce9AmQ@mail.gmail.com>
Subject: Re: [PATCH v5 3/4] lib/test_kasan.c: add workqueue test case
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="sNAUb/6E";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Thu, 3 Dec 2020 at 03:27, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Adds a test to verify workqueue stack recording and print it in
> KASAN report.
>
> The KASAN report was as follows(cleaned up slightly):
>
>  BUG: KASAN: use-after-free in kasan_workqueue_uaf
>
>  Freed by task 54:
>   kasan_save_stack+0x24/0x50
>   kasan_set_track+0x24/0x38
>   kasan_set_free_info+0x20/0x40
>   __kasan_slab_free+0x10c/0x170
>   kasan_slab_free+0x10/0x18
>   kfree+0x98/0x270
>   kasan_workqueue_work+0xc/0x18
>
>  Last potentially related work creation:
>   kasan_save_stack+0x24/0x50
>   kasan_record_wq_stack+0xa8/0xb8
>   insert_work+0x48/0x288
>   __queue_work+0x3e8/0xc40
>   queue_work_on+0xf4/0x118
>   kasan_workqueue_uaf+0xfc/0x190
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Acked-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> ---
>
> v4:
> - testcase has merge conflict, so that rebase onto the KASAN-KUNIT
>
> ---
>  lib/test_kasan_module.c | 29 +++++++++++++++++++++++++++++
>  1 file changed, 29 insertions(+)
>
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index 2d68db6ae67b..62a87854b120 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -91,6 +91,34 @@ static noinline void __init kasan_rcu_uaf(void)
>         call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
>  }
>
> +static noinline void __init kasan_workqueue_work(struct work_struct *work)
> +{
> +       kfree(work);
> +}
> +
> +static noinline void __init kasan_workqueue_uaf(void)
> +{
> +       struct workqueue_struct *workqueue;
> +       struct work_struct *work;
> +
> +       workqueue = create_workqueue("kasan_wq_test");
> +       if (!workqueue) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +       work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
> +       if (!work) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       INIT_WORK(work, kasan_workqueue_work);
> +       queue_work(workqueue, work);
> +       destroy_workqueue(workqueue);
> +
> +       pr_info("use-after-free on workqueue\n");
> +       ((volatile struct work_struct *)work)->data;
> +}
>
>  static int __init test_kasan_module_init(void)
>  {
> @@ -102,6 +130,7 @@ static int __init test_kasan_module_init(void)
>
>         copy_user_test();
>         kasan_rcu_uaf();
> +       kasan_workqueue_uaf();


Why can't this go into the KUnit based KASAN test?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdaiN%3DJ0TU_AjAoH%3DECNC8dJWS8HTvJs9nxBkJce9AmQ%40mail.gmail.com.
