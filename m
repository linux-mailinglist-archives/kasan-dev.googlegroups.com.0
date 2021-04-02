Return-Path: <kasan-dev+bncBDFJHU6GRMBBBH5WTKBQMGQEAMQLDWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C4E435260C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:18:40 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id h30sf3804178wrh.10
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:18:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617337119; cv=pass;
        d=google.com; s=arc-20160816;
        b=w8ocL81N9oiGEl+tP7tOSGsOjzA/n1Sb6LoV4JnPu/o+7q+HQHsOqLnSkuVmVDhXgZ
         Z2N22mzT/3fK4kvxDMnldDRLb8jOWdzY21I4wbhl3mp/BxI3K/ZKSAjIfphgjUGr5K/R
         jLs0zgUeLvjVgC6zWWJYkwoUk/DIZpM8HvrlQGNUtGnsRJ/RMDeQOSvnpojePNwp+cUn
         aX5BVuoN4Ma02OTdXXfrmSc/nNG+OP+wVos5zKs5HBG9LGNV68ZmcUGWc/k7WW7LgIyI
         tZPh4zWwGkvyEL9BIW7IOPcDvoGjQ9820YgO8WwqYV4X/qktKWy93ALv1p0+z9Pb/f70
         T7SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=sajanOB/XayBcRIFo7dQYHTnALSmKc/xlBNNSFHpSqA=;
        b=OVOKtJ8O0HaGuvAJuzN0yBPGIBk4wSI1nydgNM0iwy7qTTwDTeTQUswBg/W8fH3A3b
         q7CMe4U8cj+6nn5ula5XzSsYnlohUUstTWRmvJi3mZ4cJFDtOH0m6/GF/+E9uRSa4I5r
         LEjnnLi2sEsHc0C/btSwgYQoBzKxBJYzd0DPUqhZWt0ykbdq+o6nIb5VULNFIqIz3amg
         +H3mM1cDsPP544tBbqiLauhy5lrtSz12warmVckBvniRnpo2LSXjhfOKpoTm2Cv9b4l9
         FaAfRL64gl0bvaWIjOKwfDJ7sXsvUREVRSukqghQkCyG3zh2Kyd0ILN1ZkFqmqWQVLg/
         QVtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b="BiN5pFW/";
       spf=neutral (google.com: 2a00:1450:4864:20::333 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sajanOB/XayBcRIFo7dQYHTnALSmKc/xlBNNSFHpSqA=;
        b=PF8lfANVAnUwWZewMox5ou+wBzLxrsvwQoSqGkEMIqBCbJSjAL6mDjithYWjQOyD+9
         feKX6NxUgdLVbJ4rM0RhWWKbNA0jUgs2f07yB8MEokNPr8dsORprg0Q+qHJy6kqFU67M
         atqNWRJnWdV0MCet4yyev3SZ1tDldYwQTf8eFr++O4mz5yK+XiLMj2ETJcojxUwWiFuG
         uFDMEN+9fLG6/GbTAVYixGo74xyr4LiePsMSpv3XXuMW6G6PRmh186WQnCa+eODlo6EB
         5ysTnvey2xh5wH+zNemKgC9RgsAw5czsKPxvvKEHA1b5LI1Awm8nLueM58pI6gUXTdPd
         rmjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sajanOB/XayBcRIFo7dQYHTnALSmKc/xlBNNSFHpSqA=;
        b=Hs7Wq/+YGFpmjLFaBI99rpkXKcGfwNMaOsLv20UAD0CocPo7yN6Rav6MsO38wETvjB
         yvvuD28LzUyqcECsZmUwW6RQmVv/KSrvFNMyDF7SobJAAAesIXB+FjALkz3gCqYT1q1V
         C4mlZC7Em6XPNtY7rGn74KAzYswwM35L2m4Jx4i7f5/UxnyZrZ709riMsItwMdZlAUb4
         IM1b6syysIqlFczpr/2s8cscoXbLyKFMBkFnPKlEwrQ97xbQTQSXHQXP7xix6thEWhLw
         o24fnKQahdkBlEoFbKJx/+3gDwJ3QDule8b+39Y9RePPtEDp1uTVyU6XF1AvTvVbeTyu
         hnmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532M7dbzqvKXTYvRaCqocn39s4urW85wMlSw4FmK4CXwWT78KVll
	Fdvh5ixWDvxVLyRv52H7Qqs=
X-Google-Smtp-Source: ABdhPJzwlvvFUdzVJ4EAD95vaDdxNhWSI68HHwK/Z4lLFWvhXETigMcidW3u/sKflNmoppLLJ/kpyw==
X-Received: by 2002:a5d:670f:: with SMTP id o15mr13318100wru.349.1617337119849;
        Thu, 01 Apr 2021 21:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1c8:: with SMTP id b8ls3436014wrd.3.gmail; Thu, 01 Apr
 2021 21:18:39 -0700 (PDT)
X-Received: by 2002:adf:eec9:: with SMTP id a9mr13159100wrp.252.1617337119051;
        Thu, 01 Apr 2021 21:18:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617337119; cv=none;
        d=google.com; s=arc-20160816;
        b=KiFRwgZXrx7Tz0OW+aA74raSBHR6+95Ca9frVNmKp6X9qthkDEIkkCHALqljwtfr3w
         pi5Kb1hH8UJTgxk6g9OvBJGRzQXZuduCiS+575VH2Z4WRL3iGKdZGwFPhqxdm1hIpWSm
         A2EeL/D2HmBqAnkJbtpMpo0lyGEcpkZXA3nmeJ2vtfa1oJeJHRIQQfueREA0OM90xBO1
         Et96EoO70j3iNNyYUzRKI10sCPugc4+YULU1W6wC44fdQh0Zu67YZlTHxvRQ8DmTCLN2
         2JMwCxJ4mJ1AqYhYUUi+YtjrmNLIUJD2XFiMocbDzz4ErAnMxDNgAGtPal8J55c6l23+
         AVdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gEf69q7AWE2x1/Rq0Iy3chkYVF+eXWxDAEWrpJWIPb0=;
        b=XInDCk0F9tdyiLsV/wwM7LRX5ogMb6IgwHTa6gQzhiy+bU5xNW5GHJO7+5S2hgW5gi
         k8LUbB+VMlgtl9/RP7SICt52hvII0SlN5ceWeKm6CZCk+ESDT4o/0Re38rfXuAPeniK0
         DF6RWzsB5f7hbwXcMsnLObzsmtgtn3FA9S2Ya+ok6b5FoNOiKuO+3wgtCBa4trwUqJPg
         9ZZi9+momk3D25nywI4d0iL8R4ojZC/nfLM9JTc3DvZtF6C7jQB9GcXtoG6W38hVtWW9
         LT6r/sV5lYidJbA6g1ftCuQ7RgLGIzJf5qMrrw4UmdvLfGLLAu5wlMb+VvKp++nQplj5
         ZKHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b="BiN5pFW/";
       spf=neutral (google.com: 2a00:1450:4864:20::333 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id a187si42326wmc.1.2021.04.01.21.18.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:18:39 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::333 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id m20-20020a7bcb940000b029010cab7e5a9fso3766905wmi.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:18:39 -0700 (PDT)
X-Received: by 2002:a1c:60c2:: with SMTP id u185mr10663309wmb.157.1617337118714;
 Thu, 01 Apr 2021 21:18:38 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002900.470f3413@xhacker>
In-Reply-To: <20210401002900.470f3413@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:48:27 +0530
Message-ID: <CAAhSdy0mYFTwhPEHVU11yFzAwUMR_wZx3LtA0KF11wW=wNu_zA@mail.gmail.com>
Subject: Re: [PATCH v2 8/9] riscv: module: Create module allocations without
 exec permissions
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b="BiN5pFW/";       spf=neutral (google.com: 2a00:1450:4864:20::333 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Wed, Mar 31, 2021 at 10:04 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> The core code manages the executable permissions of code regions of
> modules explicitly, it is not necessary to create the module vmalloc
> regions with RWX permissions. Create them with RW- permissions instead.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/kernel/module.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
> index 104fba889cf7..e89367bba7c9 100644
> --- a/arch/riscv/kernel/module.c
> +++ b/arch/riscv/kernel/module.c
> @@ -407,14 +407,20 @@ int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
>         return 0;
>  }
>
> -#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
> +#ifdef CONFIG_MMU
> +
> +#ifdef CONFIG_64BIT
>  #define VMALLOC_MODULE_START \
>          max(PFN_ALIGN((unsigned long)&_end - SZ_2G), VMALLOC_START)
> +#else
> +#define VMALLOC_MODULE_START   VMALLOC_START
> +#endif
> +
>  void *module_alloc(unsigned long size)
>  {
>         return __vmalloc_node_range(size, 1, VMALLOC_MODULE_START,
>                                     VMALLOC_END, GFP_KERNEL,
> -                                   PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
> +                                   PAGE_KERNEL, 0, NUMA_NO_NODE,
>                                     __builtin_return_address(0));
>  }
>  #endif
> --
> 2.31.0
>
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0mYFTwhPEHVU11yFzAwUMR_wZx3LtA0KF11wW%3DwNu_zA%40mail.gmail.com.
