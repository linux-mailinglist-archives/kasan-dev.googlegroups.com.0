Return-Path: <kasan-dev+bncBCHOVJEZYIARBDUUW34QKGQEKE62BNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A704223F1A7
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 19:06:23 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id a8sf1884223plm.7
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 10:06:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596819982; cv=pass;
        d=google.com; s=arc-20160816;
        b=pcyfkKKx4F43T/OjQkvp3iveginXz2pt+EvC+5qMj897kMhXVGTVtdAX5L68wkXCvM
         ZIldbVT50omKBfoObGNUMZ0DR1OdRpe3Zh44nKFUMV+5sENvNiPGq8NEHLpIZwwes386
         9FAFQzEs4+THTzdtp/62bRsvnJWyHmVGJR2VVQje4As2XBbWiZBxN9D/I9g6AQD/XEWT
         b3TTYm6zzUz1TiF1+bdcrKwFQ5Jm+rriUiOPSD9sod/IxYsf3nntvKpZvf6nuAu+I41T
         puua/bsZAzL6Xr9KuVeEp/HCp/sYciCNS4KVUYGNWznaopPBFcvZn/hYO7+QQZ/ft3s2
         JbHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+Ux1o4FSDFgSAbaq+6i18g1eVV0wqrB7WAtWupuw4g4=;
        b=PqVKGMTP0LJo5fyRWfM31yzrep2Dev+q1nXFK7BLgS8kx+mKMaCAxZ+u7fV6yeZvZ/
         BP2YGuyq+kz9DlmVhXTw7JXW/2elwGKO9A4WjJ+3uwCspx1UvqZI2fnbNYaIbQKk3wux
         wv2ZUxUBDLJcs6Y8W9A7c2owucYiCTdSCo3X8d0vewbmPdM6bH1UHS1Ip3MHZWVpUIy8
         Q2mcZhSfw4MmwA+cu4YS+rA1fMU7EfpqMe/q880Z+YqsaQ9uR00iBF9zrjddHcnUIQjI
         N+egxZTp0DhHf3fyhd0MZ+I0kyjPaVDVhLUo3le3qBnwhV+W6HppAiiMrnS0A1Ygs+tt
         hmyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mkcM7xiA;
       spf=pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=penberg@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Ux1o4FSDFgSAbaq+6i18g1eVV0wqrB7WAtWupuw4g4=;
        b=QZZOOA4TsCyoN6E29ZPqH/UdEHfNt0YHlUXmuYh+V0J6FiaJSrYJeU7twp8r4Z6jYS
         sIrZ3k1aDVuKe6epGDse1Jv+pDJl6R+C++k45a7RYw+w8LRFMNeZcBRT3crWaBe3j0sx
         4fa/e7rpFklJ2Ydq7kCBRKKGE63Gzs7x/Gpq4jM4WAlRXbppWbcq71gcEZnJOSdCPDSF
         jceii8mXDh4XlRsmJ2UD1xYUz3KewOSm6myN20ohj/R/qtN/cywoVunsLh3uH/aCv82b
         /reNad+7lPcfFEIhzLpKpklS2fqRuyyATHKpaZ+f2qbf5mvFlvmubXDVmAuwcQG8GKpi
         55Lg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Ux1o4FSDFgSAbaq+6i18g1eVV0wqrB7WAtWupuw4g4=;
        b=QHvLWKvwe3N14cJ5tsMh13k9Dr2nyjxi2+/EaBPJYGQz17dD+3eUsBfJ675ctBIeg1
         YDTVHsYz4b2HJH5FiidHOyUKoVkeUMLYS1gjGuZ+HoQQzaBY26AYs8bN5jKq34TuR2z7
         j9K5wkwx9+Jb4jn/5zBkQILfBpXI26fzjqI2Wd3c0jeKALY/iL58iXsNr85zle9JpT1+
         iDc8p661gshzlmEOBEXWHZAnrbDrsMYSSikyDeJckxiw46tV5pvTS/Ry9EKv03quOc65
         /fUORrue8e3h2m4bMwJnxF0OWJ0bhNDioHCAtr9Bd8HaK7zJ6fubqcIenvUNZY8z2gT/
         1G6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Ux1o4FSDFgSAbaq+6i18g1eVV0wqrB7WAtWupuw4g4=;
        b=lBmH5VeOHK650Z3QsLmkfJo85SjGnEFsrREAiERBheR1WereYZ8uk+JtFw6oBHEQsU
         barQmK75yozU0ndZncyS5nOCmR9+HZJEj6D5iU6ZZ9QDNnbYXlA9sx/Y1xeJY8At5D8P
         j/pjlel/VxNcv8WrvCOPGORLrnhAFOyig3nHepYq/bEMfgc1vRrM43RtJr/BnNY551z5
         A1qwbkWXjxMcchKLGCpm8VBCoaMgqjKsDgu39jFIzSkEIj5z3IaV+Aw9HhDF3dBFFbje
         gDKcn9MA4YYVgiysr7LegAVIAtcY2Mu1O6vF/oiCxxYIj4n/9NkDgLsfOEg3goAlgDub
         oISg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326TAmj2+yqV4pfGiVDHXhhCdjjxmGRxESikz+XeMaDHIRII02x
	1y0/XIcXp5AKZT70LRWr/F8=
X-Google-Smtp-Source: ABdhPJxCy+AGuJQbPa1fFBoJRtWhfhW1+6XZ0KdMHlDeiQFcCae5kkO3oqtlwpTwU/aEFicOyPcfFA==
X-Received: by 2002:a62:1ad0:: with SMTP id a199mr14721122pfa.56.1596819982281;
        Fri, 07 Aug 2020 10:06:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca88:: with SMTP id y8ls4053271pjt.1.gmail; Fri, 07
 Aug 2020 10:06:22 -0700 (PDT)
X-Received: by 2002:a17:90a:ce0f:: with SMTP id f15mr13973548pju.96.1596819981916;
        Fri, 07 Aug 2020 10:06:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596819981; cv=none;
        d=google.com; s=arc-20160816;
        b=TbF7EOfvuvXEwWd6EH+2Azntv91IaJ61eU2SwFttAJI6L7oDJL5SAYHFckixLOFoiF
         hIfG4g+HjCCvVau/nNIQDDlnap/NrtzFNG9q/VHSoDlgTuF3X+n/s9bT0Q6/5vV37FIt
         qd1Tz8IheAdIJ+QKWHfE4HunNWNE0SlAvFsizE7I36eQ+iiwi0E6pHT67Z16BFrHzo7h
         N8HG0IMTuGT3yTgSOgbgmRyKzQo/zDgtEQHVogRFE+K3vaouVFGTtTcimLwLX6qnjZwC
         e915nWm1qteO4KNApBGUXSi+3yQzxKTGAGRszc9ca01ZEnX3FX6iXpegQUyMaFBQzkyU
         K2wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zGNzDMtgwMSgmAFRgpJLjT+o9IjR2c/1gKwHb2BF5us=;
        b=S8gnMWhJFO1XBsUr96l6n8cGM8B599WB6lu0XJTxenxBmnIesznFojkQS8SPKovt9c
         X8kgx0ZzBf+FdIi18iDCjlMF0bXkmua9RZ+j4KI87zuS5BfBw6q18Ma82cSMt5LmUXET
         bQgJDKF0xFLm7ZsignJS43/LMtDSY5qdusz+BAN/iN+gNYlA2xpXx/UyKn2HpoK2a0ut
         8xOFBVJV9WGG5YkKkUD7C1zEr9dI4UzWEGrfM0vghwIv7JU7MaiSth3pKYQg8P1JNZp/
         O3sxffVIoVr6SOEoXD/YhzxqiaP7+q46L+FmECwLYQTYtNMXmmCLq3TzO3cFusnbNR0x
         G0kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mkcM7xiA;
       spf=pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=penberg@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id v5si484561plo.4.2020.08.07.10.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 10:06:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id v13so2491311oiv.13
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 10:06:21 -0700 (PDT)
X-Received: by 2002:aca:4a96:: with SMTP id x144mr12050482oia.163.1596819981235;
 Fri, 07 Aug 2020 10:06:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200807160627.GA1420741@elver.google.com>
In-Reply-To: <20200807160627.GA1420741@elver.google.com>
From: Pekka Enberg <penberg@gmail.com>
Date: Fri, 7 Aug 2020 20:06:02 +0300
Message-ID: <CAOJsxLGikg5OsM6v6nHsQbktvWKsy7ccA99OcknLWJpSqH0+pg@mail.gmail.com>
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Christoph Lameter <cl@linux.com>, Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penberg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=mkcM7xiA;       spf=pass
 (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=penberg@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Marco,

On Fri, Aug 7, 2020 at 7:07 PM Marco Elver <elver@google.com> wrote:
> I found that the below debug-code using kmem_cache_alloc(), when using
> slub_debug=Z, results in the following crash:
>
>         general protection fault, probably for non-canonical address 0xcccccca41caea170: 0000 [#1] PREEMPT SMP PTI
>         CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.8.0+ #1
>         Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
>         RIP: 0010:freelist_dereference mm/slub.c:272 [inline]
>         RIP: 0010:get_freepointer mm/slub.c:278 [inline]
>         RIP: 0010:deactivate_slab+0x54/0x460 mm/slub.c:2111
>         Code: 8b bc c7 e0 00 00 00 48 85 d2 0f 84 00 01 00 00 49 89 d5 31 c0 48 89 44 24 08 66 66 2e 0f 1f 84 00 00 00 00 00 90 44 8b 43 20 <4b> 8b 44 05 00 48 85 c0 0f 84 1e 01 00 00 4c 89 ed 49 89 c5 8b 43
>         RSP: 0000:ffffffffa7e03e18 EFLAGS: 00010046
>         RAX: 0000000000000000 RBX: ffffa3a41c972340 RCX: 0000000000000000
>         RDX: cccccca41caea160 RSI: ffffe7c6a072ba80 RDI: ffffa3a41c972340
>         RBP: ffffa3a41caea008 R08: 0000000000000010 R09: ffffa3a41caea01d
>         R10: ffffffffa7f8dc50 R11: ffffffffa68f44c0 R12: ffffa3a41c972340
>         R13: cccccca41caea160 R14: ffffe7c6a072ba80 R15: ffffa3a41c96d540
>         FS:  0000000000000000(0000) GS:ffffa3a41fc00000(0000) knlGS:0000000000000000
>         CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>         CR2: ffffa3a051c01000 CR3: 000000045140a001 CR4: 0000000000770ef0
>         DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>         DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>         PKRU: 00000000
>         Call Trace:
>          ___slab_alloc+0x336/0x340 mm/slub.c:2690
>          __slab_alloc mm/slub.c:2714 [inline]
>          slab_alloc_node mm/slub.c:2788 [inline]
>          slab_alloc mm/slub.c:2832 [inline]
>          kmem_cache_alloc+0x135/0x200 mm/slub.c:2837
>          start_kernel+0x3d6/0x44e init/main.c:1049
>          secondary_startup_64+0xb6/0xc0 arch/x86/kernel/head_64.S:243
>
> Any ideas what might be wrong?
>
> This does not crash when redzones are not enabled.
>
> Thanks,
> -- Marco
>
> ------ >8 ------
>
> diff --git a/init/main.c b/init/main.c
> index 15bd0efff3df..f4aa5bb3f2ec 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -1041,6 +1041,16 @@ asmlinkage __visible void __init start_kernel(void)
>         sfi_init_late();
>         kcsan_init();
>
> +       /* DEBUG CODE */
> +       {
> +               struct kmem_cache *c = kmem_cache_create("test", 21, 1, 0, NULL);
> +               char *buf;
> +               BUG_ON(!c);
> +               buf = kmem_cache_alloc(c, GFP_KERNEL);
> +               kmem_cache_free(c, buf);
> +               kmem_cache_destroy(c);
> +       }
> +
>         /* Do the rest non-__init'ed, we're now alive */
>         arch_call_rest_init();

Anything interesting in your .config? The fault does not reproduce
with 5.8.0 + x86-64 defconfig.

- Pekka

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOJsxLGikg5OsM6v6nHsQbktvWKsy7ccA99OcknLWJpSqH0%2Bpg%40mail.gmail.com.
