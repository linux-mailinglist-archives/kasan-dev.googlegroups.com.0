Return-Path: <kasan-dev+bncBCMIZB7QWENRBOEHU7YQKGQEV6X7HDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F37E146DBB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 17:03:06 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id dw11sf2256591qvb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 08:03:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579795385; cv=pass;
        d=google.com; s=arc-20160816;
        b=WDd7CG7tk2NbHv+361htIyrCv/t1AKcfJW4REwlRZ1QACbc3gMj3HFoqDm0iNGDbo4
         yve6WqY+rQiaUuo6dy/WVwXM04L7FidSEkBLR3MpK5Te+e+2TEnz5VHM5Mu6ekOM4Apc
         xK4K9aE057NHXLQjXI0WBaLFGpKq+YEUb98dPieku7biLEy6OLNrPfLYmIUyE5RZ6XwX
         vviXO5yELQOKHzBhiL190jNjDKqTqhiUcmPgmIdPBAIYp12wrEhThJkQ4Tfqut7Yaqe/
         OgfGFaTfPcsRYGhGrQpxDxEewk2EJCUWLJVt2NDolh+2MVwneRjkMJR+CLQ0G6rho1tS
         31xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HKfuMHnmHafccXycoKCaZbe68CYN+Al3GJbPR7xNkWE=;
        b=v02VDlTp7947hncAPIWQM+Oykd9M/uX1WEhmgszjdmMsqXPk5HgAALzNBW+OJaAcZP
         xkq0loGQxEYE6owsKVkSu71mhYMP3zFHan7pfgxlIYmw/U74yMtNvm1BiwsUBjqx74sR
         +J4YaQB05WMIvLeEdlKNEsB0wllXQbC6kV4b7XrKEEG2GeTIxscAKhYkmtaQxk44ofOJ
         cCh9Kxgojlath3edegv28VAqTX3ERhyE8pGsTS1EUMk1kuH9jT1XQDyLH/tDSSJnuVH0
         sCKJTO5GfJ+7ESDz3dOEjrWQGjWwj+6c8jlv0AbXpAwBtXjtIj8ejPBGlgMX87nMGF/O
         9eeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VMc+2vTz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HKfuMHnmHafccXycoKCaZbe68CYN+Al3GJbPR7xNkWE=;
        b=a/Lb97y4A5bd9MKQOJTr1g7PmszzeJ009IOnKJglwn7kMl9bHJ/TAJb3+VV0+AOYQS
         JBRmstL80LQiVo4BZCXlVjl7XiVD168jAb5/064rPzv5bqvBxD0BCeJakCXEswBo/eLB
         BX1AU/8jECpoPaWGLiVThWUtz11gibAW5dJAHP5P+W/lG98ZUtcrqbJ6tCX8ggbNMJC+
         ZZ7BNnfTs2OvFr64EN+oC7qB0nGxpOElTOqKoyZyZH9EnHtmHfpIL+vZRevsnUIZ2GHh
         SqNJqEpq2A2Z6nPuA9O7aKD0nyCTKf5cxV50XWDsRoXAzgIrJiiDBDQw81c+2c0qlalD
         HqHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HKfuMHnmHafccXycoKCaZbe68CYN+Al3GJbPR7xNkWE=;
        b=NgoWpln0lti34dsDrqItHBlAXCQiJSX4C3r8uA/+iPBHSgI3XZgFvZmb2RoIjLruff
         Ga9f42uVOeMHfApS1hGlVwpkYnFk1q12mJ3cHycvR2gjC2yjuFj+CgpTILeuCTNslwMX
         iHtZX/UATn+08hHM6MJ3s7cekBTOmJgfU4AIZgMX15I1mn87HqypdzhGU9Dz6XBjz4S0
         Q7sjDZaJhun7ue/PZ/hiVpTwn7P2Y2cvQBz7jridhC6HLE9ahZ+liVblc9+ofG7TOtff
         pthX4mTd+BSYL+wkcUHLJhyzch/Yl3HrzRLm2LCnnMETHBoipBvl7aJsmDWbinzlwCSM
         WvLA==
X-Gm-Message-State: APjAAAV2dY5iuikIeyr0CffHHuLq7cxLnWRf2rlOLDiSOPt9xUwoGwxj
	cP1wvNbV22kgJUGFHlb2rgE=
X-Google-Smtp-Source: APXvYqzE/FZlZdpVmGWS4q0GlHhrtGG6rYOzkaG2mJFkwVfc+1EKhmnBbEJYfkjM9vZEdeA7hPT2Zw==
X-Received: by 2002:a37:7cc7:: with SMTP id x190mr16573115qkc.10.1579795384624;
        Thu, 23 Jan 2020 08:03:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a903:: with SMTP id y3ls633153qva.6.gmail; Thu, 23 Jan
 2020 08:03:04 -0800 (PST)
X-Received: by 2002:a05:6214:3aa:: with SMTP id m10mr2594316qvy.125.1579795384270;
        Thu, 23 Jan 2020 08:03:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579795384; cv=none;
        d=google.com; s=arc-20160816;
        b=RAN1Wyd0iJho0vt5nrHVjHujsDBMhBWaqTvUSo5HaewLOBvEYw6Sftpm3FNNXfw93H
         4rCh9/eBPoNGoyjrzzPH8eMkpgHiEGD6xti9FnA2/NUFIukXXBx7XdmuDrqOgJgO5j2x
         wUCLVkCg3gtiRsIixDMJVMeZ6xxUT9fwjKTr2iQhjB+snk/UZQqgBQO7GQYfH00ph7rc
         db778Nu1bbHo9KTSBkeVXD4gWGmpCYg1o0YQuhG6sbzU9sCiD5K2Sv0MlXB5VsPkfTNy
         wWY4ADNzK8EsuGGq9+Pic0FRRJ8Wrvp+NdqaPcjHxlM5fu4sZmMK7aOYDbMQ+oxpkKkK
         sNNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Zrh7fW80iw6PG+VKgzM4cKv470tUdMXSG6k6nsxdjg=;
        b=z3JKeTj8H96mwNhgLbBvdm6PRUC0+5XR+Wkux5iEa+6Lnc1KPFblANEjw3uBWj8lbq
         KelSCyFEFBsySJwUgGF2pllXQ4E6F/edJ6A8XV3vqoJfxfOkds8mBJDeEg0u854+7vMh
         aCYj9Y0+D7ZpeknN9SVvF0Si2KRK8VB7trY7r6XFd0ecs9i+xjvhJ2y8J1UoSUYBtuIy
         pQaDLUGeB1WwBz0xbJ3N+bXWDAjfJMj0gintPLZMBbH6Y55yn54So0wRVzSCmswMSJtY
         PBbPT2uDs4v/b1pLS8u3M+o62LmMkj/Pvxdo+7FW1rR5TUblB2GKuqPngrs4tm/aO7Gy
         CPLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VMc+2vTz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id w9si71090qkb.3.2020.01.23.08.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Jan 2020 08:03:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id j20so3873916qka.10
        for <kasan-dev@googlegroups.com>; Thu, 23 Jan 2020 08:03:04 -0800 (PST)
X-Received: by 2002:a37:5841:: with SMTP id m62mr16346928qkb.256.1579795383649;
 Thu, 23 Jan 2020 08:03:03 -0800 (PST)
MIME-Version: 1.0
References: <20200123160115.GA4202@embeddedor>
In-Reply-To: <20200123160115.GA4202@embeddedor>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Jan 2020 17:02:52 +0100
Message-ID: <CACT4Y+bOxBb_fy3jak=prrznOPEbm+nfeq_yUC8yrU+-3RP2UA@mail.gmail.com>
Subject: Re: [PATCH] lib/test_kasan.c: Fix memory leak in kmalloc_oob_krealloc_more()
To: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <adech.fo@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VMc+2vTz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Thu, Jan 23, 2020 at 4:59 PM Gustavo A. R. Silva
<gustavo@embeddedor.com> wrote:
>
> In case memory resources for _ptr2_ were allocated, release them
> before return.
>
> Notice that in case _ptr1_ happens to be NULL, krealloc() behaves
> exactly like kmalloc().

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

The scenario where ptr1 is NULL, but ptr2 is not NULL is not impossible indeed.

> Addresses-Coverity-ID: 1490594 ("Resource leak")
> Fixes: 3f15801cdc23 ("lib: add kasan test module")
> Cc: stable@vger.kernel.org
> Signed-off-by: Gustavo A. R. Silva <gustavo@embeddedor.com>
> ---
>  lib/test_kasan.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 328d33beae36..3872d250ed2c 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -158,6 +158,7 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>         if (!ptr1 || !ptr2) {
>                 pr_err("Allocation failed\n");
>                 kfree(ptr1);
> +               kfree(ptr2);
>                 return;
>         }
>
> --
> 2.25.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbOxBb_fy3jak%3DprrznOPEbm%2Bnfeq_yUC8yrU%2B-3RP2UA%40mail.gmail.com.
