Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3WB2OEAMGQEK2Z3DZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 153943EA100
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:50:56 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id d9-20020a0568301389b02904f06f06bc4esf2082342otq.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:50:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758255; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3fRex/U2hPmxVFHolF8Rpie67gqSWQG7IF0frihk7s67joI/AZoblmoi1Yz3InNOI
         5mXoQQrZmD5P8eQ8Ryb7vDmGFG80oh3OiABJ+zUAEvMIKHvGQWetQtvUrnxafouOTAzs
         5d66XxReZuqFj5TmpgEZsBrqihJZoaJwp4JmSF0rE86dPrPV+0uEotOaw0PLkgW+L4qy
         nu7EVPsQ5Eyp8pjlZ4+y1b1gNPGxOozJfq4yHWoRTC/DK0nxrpZr8blRRgmoJqMWQZyp
         pm+gYEIvqJi4RZx+OloDjH3bzWfIJEy9eIO294FMDqSLclaKP0oC5ELh0Y4Faqfgr1ZC
         JkdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+IBTD0vY5MexpQmk8CBnw2p3imUPVJPDnL3Azlabuhc=;
        b=wCTgC0EcKoSuEwLF2jqC2j1cFa2JOQTc0mYFVLRaEU8+Seo3FDIdvzyNPG+82U2nye
         YR73nXozGUv86JOGDb2ihFuYAaErV9rB2lhsxu0oOd0EoFeE3jWCXnFXX+b9exjf2ZsS
         YyiSPvCqGbDpcIxfuR5wGef5HA2iiWFWPE623foMnpNsH5k6BOz1GWtanvhBMwHIpjkJ
         BMOkz0/0/CdCB/2jtDmmqgBaezJZ+0msjoFd9f8zZ+pVVO8EtuE90k4nAj9k2pEB2LYV
         SYtBCL7kmSI109pSaksqQ1xaCDkCB1Zhm5j88qEzOjNxgA0U6wMTopqllI7DFui0iP02
         VNsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNp1TxiR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+IBTD0vY5MexpQmk8CBnw2p3imUPVJPDnL3Azlabuhc=;
        b=aq0CAMWeB/g18wN6uNk9WI0K6fwCYMZ9ruGU7N1ilVFMgndjB3KTnl8z1AaNtqNSB5
         +QMGUgzd2aQCPKmKEEAEfb68gWW0Ph9Hvv/gLldPNE6ZZ+h/dVaDRWcluFSVL+5kn2oB
         hiHu1RS3JNNoRQ2O6Toynbnnr96eGLAYucwplu7TSKbrnhkElTixWiwhB2/RDesGbnZS
         BxP2xJC5YPuvQoaOtutKRCW3y6WHqtPKe0IH+wkDzVKcISgH6LKpoRVBqqucJMmobWKF
         n3em+J9Z/7bFrjpXeA/0oh+O6PR6NxHFXi81RGpzSSDIqPzzhb06go/6FrgKatH2G98h
         aEJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+IBTD0vY5MexpQmk8CBnw2p3imUPVJPDnL3Azlabuhc=;
        b=VaTWkOJk2OUPJCsNPXsZTq/HcbnsIHqTmvvfNTV7ls9fbbyw6nfrFwIv81ym3ofRl7
         rZUIq7C+DOV4ow+u0boN6cfFEJUFotocCt7IA53DGu6806eJBPs/yS55EJV9gWnJ/PiQ
         MNtd/ypnJ7jb+qEcH4sRfRK2jA3THuiVMp2ghSlizdO27itmb1MO0NpJc8HZaOTC5qNQ
         gvQpfdJzU4Ex8dVWJkMpdtc+Nsmubei0DZjB4Db3dpboV16AMHquyK9I7eURLKyq8iXP
         EjPyyOY4G9tK4NzfgR3LHZt++eFn5BiDqICXhpB/aUj13aNdwildHOsdwtl8dgaq+iL0
         9VDg==
X-Gm-Message-State: AOAM533u4g/Kxb0D9QUXJEVjUVuiXfUWD4MANtuFFwHfEJ5V/uZyQGyb
	fORtoeY3VrfZGluQKtTQK+I=
X-Google-Smtp-Source: ABdhPJw1cl4gKjSf29ylHqIptJBsvg5TnSRMzbFUrEXD8oGeno32OGvC+E21liy+cm5gpx3yVzLvXg==
X-Received: by 2002:a05:6808:14a:: with SMTP id h10mr2544514oie.17.1628758254859;
        Thu, 12 Aug 2021 01:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1509:: with SMTP id u9ls11620oiw.6.gmail; Thu, 12
 Aug 2021 01:50:54 -0700 (PDT)
X-Received: by 2002:aca:bd8b:: with SMTP id n133mr8943583oif.75.1628758254520;
        Thu, 12 Aug 2021 01:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758254; cv=none;
        d=google.com; s=arc-20160816;
        b=TAOjFVmGvmzdQJzEqqxO6BlWzCbuo80horE9eNTHfOkKycyOSTKGUzU6BhoImsOwSy
         0rwDHwRSAf7Fr7mqPBtliLRjoUjklHHVo3zP4gZXM23Yqtsm1kzVleRW7qXzVjnDMPIm
         Fw8HEV9tWCHTZ2qS/STFsc9LLcx91bXILo2R63t/NMQ1aV7vJCHRV7Z4HkBqbbOQbtwm
         8RDzNS5LB4Whj9f5355lJ+UHVKCn2SKMhaSHl1SXya+23hnljcSzbHMsKnm/ZQWRkmU6
         MpLIQ/wj1UBBB/k3DkOuH1q0rKCvkE//VhEooQz2gE4GR36rFrny1BspdKhRZHWkuLNO
         bxCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L6hRQLk+mDuzM1tU9wPV9OpAoS0YdU979SiyLqR9lWg=;
        b=CAk8d5vbiObBWBvBbYaB26wTsuTrp8J6FRhYzoaOcdEg6Elox2zhOZwGkEQHIqIoVC
         rTWHycT0RMrwzl+PDbKjle7AWg23acOdAqTWiWYysdiL9Up+cg5CWf02s8lkdtwrd8rf
         TDPUR82wQqJNZ488cgWO4jh6Pqky/sVubnPdWVi7giauqlPgbfFQevFhRmBblYxU4YFg
         xuiWYLIJTCMzpibx4W8aYcDM6k4PV9n3ejA3ExEYt7zRPg7wM1ixpZWIYc9Gb+TpfvQz
         RJBYjYUWAtrJQlEtr9/3dCwGmetqRdUBZYbW1klYOuxPjcNap1pnSSctPiIOz08yybNy
         P32Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNp1TxiR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id m17si173319otk.1.2021.08.12.01.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id v10-20020a9d604a0000b02904fa9613b53dso6853220otj.6
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:50:54 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr2681205oti.251.1628758254073;
 Thu, 12 Aug 2021 01:50:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <17b812a3c28024acfca9b1a9e45c8235b35efa32.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <17b812a3c28024acfca9b1a9e45c8235b35efa32.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:50:42 +0200
Message-ID: <CANpmjNMYJw9Qv48tsC-EVwKDeG9FWCwmf3SLZzATyfGoMDc2Qg@mail.gmail.com>
Subject: Re: [PATCH 7/8] kasan: test: avoid corrupting memory in copy_user_test
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tNp1TxiR;       spf=pass
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

On Wed, 11 Aug 2021 at 21:30, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> copy_user_test() does writes past the allocated object. As the result,
> it corrupts kernel memory, which might lead to crashes with the HW_TAGS
> mode, as it neither uses quarantine nor redzones.
>
> (Technically, this test can't yet be enabled with the HW_TAGS mode, but
> this will be implemented in the future.)
>
> Adjust the test to only write memory within the aligned kmalloc object.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>



> ---
>  lib/test_kasan_module.c | 18 ++++++++----------
>  1 file changed, 8 insertions(+), 10 deletions(-)
>
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index f1017f345d6c..fa73b9df0be4 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -15,13 +15,11 @@
>
>  #include "../mm/kasan/kasan.h"
>
> -#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
> -
>  static noinline void __init copy_user_test(void)
>  {
>         char *kmem;
>         char __user *usermem;
> -       size_t size = 10;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>         int __maybe_unused unused;
>
>         kmem = kmalloc(size, GFP_KERNEL);
> @@ -38,25 +36,25 @@ static noinline void __init copy_user_test(void)
>         }
>
>         pr_info("out-of-bounds in copy_from_user()\n");
> -       unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
> +       unused = copy_from_user(kmem, usermem, size + 1);
>
>         pr_info("out-of-bounds in copy_to_user()\n");
> -       unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
> +       unused = copy_to_user(usermem, kmem, size + 1);
>
>         pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
> +       unused = __copy_from_user(kmem, usermem, size + 1);
>
>         pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
> +       unused = __copy_to_user(usermem, kmem, size + 1);
>
>         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
> +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
>
>         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
> +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
>
>         pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
> +       unused = strncpy_from_user(kmem, usermem, size + 1);
>
>         vm_munmap((unsigned long)usermem, PAGE_SIZE);
>         kfree(kmem);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMYJw9Qv48tsC-EVwKDeG9FWCwmf3SLZzATyfGoMDc2Qg%40mail.gmail.com.
