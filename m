Return-Path: <kasan-dev+bncBDE6RCFOWIARBX7X26MAMGQEKX5MS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C4635AD415
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 15:38:40 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id q5-20020a2e84c5000000b0025ec9ff93c8sf2887527ljh.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 06:38:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662385119; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6xBDCjCuPkdQSqA0bl6yMaX8ESOzAQasJmzUXCfQF4C5k+FlzSvd7xZrA6NMH9147
         zWfB35E0pQuVgvo1SexkJ7vEZWYogD1HLRk0zTpHlSfqGZcm9QpkQr19U86dKCoP7bj9
         T0qQHZkZ25n1CCgtJIIq3whSXWNE3V1wDPVchrACUCr3/wrXXs//N6ZyqzI+TUexUChP
         2JYCJQPMi4SXk0RsedjoWGFiSFd7DZmpYdwZAB4Kdt5cn4bNOjk5TbvGHP2cJnLKuTpQ
         MdnoGq9VhmOW1RS85bfnc5QB6D4vL9J4F/pJAwdVxJnPqyBYgtIrCUGZCya9NCWIEmLh
         uL7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ggiaDW1WdSkO/P+63x2PCwK9+WW9pm58kiABYGFHPs8=;
        b=uucWBTe5HeS4+ljBLNhzKYW8S6exyG4bJ/Vjfz2Sol5gslPARrkgYuPBalZfyJRbjn
         wJE4TX2JZJInXrQhvWmDqQ3zCluSske+1MK4sY0d/0gB514+ntlzpDLPbzst6sWYKa0F
         lMwCt4P3Qc9gEiQTLRka+1NvE5R6BkAXnBvg9G8B1jfi9+KE4QddCVlNMh3fSPsKdNiF
         PqFJb6OiPE3IjYadDZHVT3Hc9TMU5FqQ1o+8moYD4hd5+vk7rXvpubrO7c5fcpay6zGj
         Uz7yBeVOXlfMELinhmuDPxyt/L6L2HxWXbf9dRiQ6mV5sAN7nRXvWjQuQxx++9Q8sjhB
         yH7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tKwz8Der;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=ggiaDW1WdSkO/P+63x2PCwK9+WW9pm58kiABYGFHPs8=;
        b=DIGnOGV8HJJdLszI6Qh/pjSvmsUjtr+qeazOsapIcHRzEjO/QYnzr1OqxLOpxjDEEY
         Rd80nint4xMc7Fczhn0vsdap7yNaVs/QVwK6Hl98UVqSV2XIF0CO6mY4Lb1+RyW9YySG
         A9f6ch78gwHg69OMpmx27viMAp5CA8VGeJpGWysU2nUSuQgJSyufvEGsTryuwkFORmUV
         jl3M6UTDeffoJ+gjnIas7nGTUfyXbsGM7YDn6LRSGcwbcpsCoZK6hPvwz/3IUJJ++22S
         4OUYZJPTUDInd9IQNdtBVkjR3dTykYOanLpUlgwRAvrlpCPiC8QnHobkxG6jWy7kBfPO
         k8Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ggiaDW1WdSkO/P+63x2PCwK9+WW9pm58kiABYGFHPs8=;
        b=ybsUl9qa1E1SZeVHTLTDjTDbBGm09BFoRxWGzV8pmBwCRP2yE7XSefbVer0PckHEEJ
         5C8cMUXfqdvC5Y4aIGVilGvAZSJIFNru9evHQvmkSmaIx43XsWnZlw6pIYxUy86gIHkj
         vUPAcZdLjdarLIHDbKmN71FQbWMnGZdaIftVkWOkcwqhkYZz40jWoNLA51TDzEBhzeOS
         0VEg/kVv5SXC7DMh1V+kNWiOeF6GrBhYMvVBeu1ZPgC4y7ALLWfnttlq4JyqQ0GPJxfW
         +/FFY7C/mB84kk5PgxXd//xlYCPjhQ+S+tyd1CHVzVFZIyEDGkt60vVofTpCgaEBN3Hk
         LPVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0fcHAN4/bAI6KibwIxVHCDcGct2IPJdU9BNUi7ApPxWJsBs4bG
	o/2A7JQmKUDkuADGE6uQPuY=
X-Google-Smtp-Source: AA6agR6uci6QRUprBiUxMAjhYYcb6joCRQXi1jeA5YZdBBsqoV7AZSCb7zTSKecHfXTwhFFgtnyWDQ==
X-Received: by 2002:a05:6512:3c8d:b0:48a:f74a:67b6 with SMTP id h13-20020a0565123c8d00b0048af74a67b6mr19075961lfv.231.1662385119541;
        Mon, 05 Sep 2022 06:38:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1055:b0:25e:58e5:b6d5 with SMTP id
 x21-20020a05651c105500b0025e58e5b6d5ls1595395ljm.1.-pod-prod-gmail; Mon, 05
 Sep 2022 06:38:38 -0700 (PDT)
X-Received: by 2002:a2e:a41c:0:b0:26a:49f1:1fa4 with SMTP id p28-20020a2ea41c000000b0026a49f11fa4mr1939708ljn.504.1662385118426;
        Mon, 05 Sep 2022 06:38:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662385118; cv=none;
        d=google.com; s=arc-20160816;
        b=Z+bV5zt29ilrycorWc30Vo6MBVi2Ofyg3Rd5xOHeyQk0s804Euq3YidYAYQ1oVDUBZ
         24//dNv+QmwJViUGf7u11L+2msoxU9XboSqp6/GPeHWSHiS0P+NEMXCrtkOHTDXTG1C7
         akxESFEN60FY7QyaaECHKQwV/0F/5g7o+j+EULHo2rMgjJU6cJfvyPoM9fahtarED4G8
         SpFmMO9tWfBo583AXNayR4poQ8gCsuV/WnlyyqzrweS0IjY1ryZjBtwckXHKhSpIFRjR
         pQtNa0s6QZDAHN2f2BjRQlU5mzFBiozHfPM0vK9HBtGpdF4wwpze2VHc4kcgbhCjxEsT
         S64w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G6oEhCANh1uMv1tR8inO3nd+yCiqobEBbYQgVB5GUY8=;
        b=G/ngHVSAqyrC+yweypM2A8QW25urANqUVPuwzp9RFRX4VogJg6iuEYORZvW0IF5xqK
         V36r+O4FPEDP3UXLpUkhaprmE9sh6Gwq1K2csTC2p57bGMKCxRVbMKQDpVRFkZsQvTj0
         D+pbDC6zvaxQxMVynCp1G9IcNNLeV+VgBUcQZ2EOIq9MzNeSUDq43z/g6WmFhVGEAGeW
         0aH42rlipLZU4mY7GpfWVq+nLJtaydHa4M9Y6whYWPXkpqgalah6CXOdCiXGMIqobMtC
         rV3HsQtwmnWx9hThQew/hvLp/tyeIJgotYFikC13cHn5pBnmy/XWO82wjUZVkY0ojOK1
         EQVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tKwz8Der;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id b4-20020a2eb904000000b0026892f05f78si446452ljb.3.2022.09.05.06.38.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 06:38:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 29so6333113edv.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 06:38:38 -0700 (PDT)
X-Received: by 2002:a05:6402:51d1:b0:448:bed1:269c with SMTP id
 r17-20020a05640251d100b00448bed1269cmr26103860edd.205.1662385117911; Mon, 05
 Sep 2022 06:38:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220905122754.32590-1-alexander.sverdlin@nokia.com>
In-Reply-To: <20220905122754.32590-1-alexander.sverdlin@nokia.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 5 Sep 2022 15:38:25 +0200
Message-ID: <CACRpkdbdKAWfvpG2n-eJPagV3Sx1faaxC9cEFs3PTyDaxETwyQ@mail.gmail.com>
Subject: Re: [PATCH v2] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
To: Alexander A Sverdlin <alexander.sverdlin@nokia.com>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Russell King <linux@armlinux.org.uk>, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=tKwz8Der;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, Sep 5, 2022 at 2:28 PM Alexander A Sverdlin
<alexander.sverdlin@nokia.com> wrote:

> From: Alexander Sverdlin <alexander.sverdlin@nokia.com>
>
> In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
> shadow pages dynamically. But even worse is that kasan_release_vmalloc()
> releases them, which is not compatible with create_mapping() of
> MODULES_VADDR..MODULES_END range:
>
> BUG: Bad page state in process kworker/9:1  pfn:2068b
> page:e5e06160 refcount:0 mapcount:0 mapping:00000000 index:0x0
> flags: 0x1000(reserved)
> raw: 00001000 e5e06164 e5e06164 00000000 00000000 00000000 ffffffff 00000000
> page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
> bad because of flags: 0x1000(reserved)
> Modules linked in: ip_tables
> CPU: 9 PID: 154 Comm: kworker/9:1 Not tainted 5.4.188-... #1
> Hardware name: LSI Axxia AXM55XX
> Workqueue: events do_free_init
> unwind_backtrace
> show_stack
> dump_stack
> bad_page
> free_pcp_prepare
> free_unref_page
> kasan_depopulate_vmalloc_pte
> __apply_to_page_range
> apply_to_existing_page_range
> kasan_release_vmalloc
> __purge_vmap_area_lazy
> _vm_unmap_aliases.part.0
> __vunmap
> do_free_init
> process_one_work
> worker_thread
> kthread
>
> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
> Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>

Thanks Alexander, will you submit this to Russell's patch tracker please?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbdKAWfvpG2n-eJPagV3Sx1faaxC9cEFs3PTyDaxETwyQ%40mail.gmail.com.
