Return-Path: <kasan-dev+bncBAABBTGJTCYAMGQECADZ3QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EB82891198
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 03:17:50 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-29de0622270sf541915a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 19:17:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711678668; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rv9peH4mRWiCE1ZMqRVS1eqh3xXix/+Ga+m4DXXuVPkNhCbM08GHR6RCSwR6sCyB1/
         5h9GoG77kZtiYFSM3mZ8oWxmGlz31XaRenBGDZecbWs7ZzU1+mABd+QD02hWaqpu1TWd
         uh6Xn2IP/GM3QOh3PmIaYaFM8VaPrgWQx0j2IVmsdjroRBqi19u7uKOWkSpvsTgmgRc9
         0cewukWl2ffOLJN1J24YPrgq8Y5KLriEkNYD9QC749+QMcymCay8uWl0jqEBi6SPsJkX
         El7cb30yna5Y/3k/wYMZU7s+7/2PaRiAU2FgI40hbqwsVAv7BH+3Ct713DweIG+cTMsU
         ZqPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=NFnvWsKVh0ey5sf/r5xYo1bNDv8mMT7P98JfiSL3RoE=;
        fh=5Jp4fCJEskjqm3lTOYypCSoAoYCD5glRvxMbER25ltk=;
        b=oM3K7mwz87cxzrYgZpjRJWsGQPx3ALwF1IAqSEfIEGRQm/BrJMyvjQA7hmTgubRlJZ
         uMvrZZNeYHJWDUQ1GQ6NFYCTl15PRa5OHEud8MLj/VFdO5EUZ9Xeqq65OYE/GSUBnb7h
         VEqDBJhUcv7uRl1YEsH30pMDMQjcCRMBnERmcpCp4AItAvTQFkkfBARrYmLVEbOq44Bp
         BGMoP2/a1wD6f/nfJjhPQ3nYC9dVmTEAohQseHD1MEw4IWurQlSXe35Tpvay8HNbADlQ
         rIKkUcpJc2sjgNi31vRhULBTBOwzb3MMm1F3bNlt9/exWo0PGhyQtx9K2qnRPnp+xMq6
         W9pA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ED74/NW+";
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711678668; x=1712283468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NFnvWsKVh0ey5sf/r5xYo1bNDv8mMT7P98JfiSL3RoE=;
        b=VM7WwXnCOARPyk6gYJlHHf6ISCoOq77F0VkR0NUGe1Lq7BLxurv/euBBGC7BhGsRJQ
         mchDqLjc7Vf0sMpE5EtbiWybpTugemCuffRR5dE5TwK6R5f114a58qJaOM34q3v4xJ4c
         ZAj4donUzvCERpr5haiR+YYNRh04GiQd1/MzI/FQYGYKU6HdJjfff6XL5yc8YhpgT/P0
         09aTDH3iOuExbf0lts9OpDXz6FPgtuvVZWpnVX/bOqs4huF0Nq6RW/vApmxZbS0YWpg9
         suAST379BKWpOrqTGnZOGFMJMBKGBzodcLMjtCBzUWhVKvx2pQDRVFo6TrpKekSV1e04
         Dfmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711678668; x=1712283468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NFnvWsKVh0ey5sf/r5xYo1bNDv8mMT7P98JfiSL3RoE=;
        b=T3mQdEk1euY8r88KHEruc9VS4F0PFqOEpfwN6E8LvuEY4n2TPwB1SC74mwKuwCM3zO
         EdXSVfla3bMWnm9xuuaNxsj+7p981yHUD3V3jbZ+ZA6tSKJ6fQHXz5wsJYYnRZd6N+6m
         feKMBqY2My7IrvxK28RC7c0xBTYKc2bsatuzIBCgP+b+P2XrCnpz3MpEOqL3TdLsmUbm
         w11CUfSUxGif4Vc4Ct90bqQPFZ+BeuT8n2Bbcqlpp1CEV0AwMBHmMNuNABNiQZAtAAYw
         I3LD47obReW/ag2qc29M/UouBWX7KwQf+M4xDXDJvIrprMnb8Ugvg+d8WVZIHbzTZupr
         4rPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUe+RrfDdjt3Lk8E1KMPRLpM+HyYLDD1vMPm1DcNVfmSnMUMus3jHb7Tsd0X96jhmmAyb4jC6EqKmk2Uo0+J0XzNOZk6NBhJA==
X-Gm-Message-State: AOJu0Yw56wtPbzd3k1942ilp+ZYwhayUqFLqIKoh6ReHQReCTyjd2QQ4
	HY7xFw/qjXEhDDL9qLJysYgsccb9LglePX6pty2Zd6ZWlvH15r2/
X-Google-Smtp-Source: AGHT+IGPu071g2bxpTNYbnAXu1FTIZcfQQ+C6tx30dPyXZ6flrPu3lj5a7ObTnJnhTU44sgKHid6Tw==
X-Received: by 2002:a05:6a00:3a1e:b0:6ea:df65:ff80 with SMTP id fj30-20020a056a003a1e00b006eadf65ff80mr1113884pfb.3.1711678668309;
        Thu, 28 Mar 2024 19:17:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3c89:b0:6ea:bc00:4ce5 with SMTP id
 lm9-20020a056a003c8900b006eabc004ce5ls1108467pfb.2.-pod-prod-08-us; Thu, 28
 Mar 2024 19:17:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXKsbJGpJ7HtJj468oVBFQC0AMAK1LsU2b4g5mXRQ/Gl5ejjS+4e6IHH8EZZu0WB0M+qBm4if9XSKkoWoil4vQd3zzd3i/v5zxFA==
X-Received: by 2002:a05:6a00:1301:b0:6e7:7d59:683a with SMTP id j1-20020a056a00130100b006e77d59683amr1248024pfu.4.1711678667256;
        Thu, 28 Mar 2024 19:17:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711678667; cv=none;
        d=google.com; s=arc-20160816;
        b=hOgyGwp81mRdW4V8bqtc8ESWB2Dr5tGqRudHI9WGdx7xqTBn8DHuT+vbKBkAmseNHK
         Dbhpi8+ah6viGlCMWEilFT3n0vnwcyLU+KPN9T4b/yuxlDlpiyVhaBHnIiwaxyG4c53d
         mSh/6F+ZaYyMxdjRBfypjKGRNJWDgUqWrBG9GjWQGtPCQNyxuqYMre2MQMag9FLmH2mb
         jdm1zU1VoDvxlQNzkxrRGVq9WmKsc9A4pFAvrxVAWgjMniLVxtP39sLgxYCT5BnSjq15
         4OS4W7k/s+jSQMDBniuBUhGTfE3Xfi5rU2fOR5ttyXleskDztoryrrQRjsuOAz8ys5m3
         YrCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=r4GDnHXGRjjHQy7Zw6z1rus9jBN4KwcIQSVFoGQ4oBo=;
        fh=VAdUlQX0NlRT7G1nk2B0Z8r73PeQn53sLtwWjzS/VuY=;
        b=mxf4bKqe2B89GpuY5qQQ56WHXcSp1uEpIgBS08EY44A8KDzzDy+iybGyg2Z37lYPu9
         yWkg/fVKBkxXsXyEro2oW6c61vFnDStzgUzWHla1CF1pHM0WYGEtiGG8VwYZYJGZvkKM
         Hj28aSvoyUHVWmhiF03LEaYQax2W34GCRtenGPYXVyN7S9r1XgeAnfTEedDcJs/UC2g7
         txSwYp0yiaO3kZfYFLiaUAFwqwy2dsCluzvTT3tK8rnR78fplBFd2vAvachryGGS6Ono
         7Pu/BATC9IQFGjcI5GLXZ9ATEQ21C47susPNxJBkBb9JfD0xFluvFG72EdJQdniuEEep
         UqIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ED74/NW+";
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 11-20020a630f4b000000b005dc851134acsi223600pgp.1.2024.03.28.19.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Mar 2024 19:17:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A5D96617C8
	for <kasan-dev@googlegroups.com>; Fri, 29 Mar 2024 02:17:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 57CA8C433F1
	for <kasan-dev@googlegroups.com>; Fri, 29 Mar 2024 02:17:46 +0000 (UTC)
Received: by mail-lf1-f51.google.com with SMTP id 2adb3069b0e04-513e10a4083so1797876e87.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Mar 2024 19:17:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVfveB2sMtGxznwnCvdzkESJ5jEY6KANGRDxn8nijc92GOKTADvVsy8imfpFwQs3JaPq85iJPWiIBmRCCiZt3RKkZvbKBSeJHRzEg==
X-Received: by 2002:a19:ca5c:0:b0:515:9150:ecc1 with SMTP id
 h28-20020a19ca5c000000b005159150ecc1mr620038lfj.24.1711678664699; Thu, 28 Mar
 2024 19:17:44 -0700 (PDT)
MIME-Version: 1.0
References: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
 <4d2373e3f0694fd02137a72181d054ee2ebcca45.camel@xry111.site> <19c0ec82-59ce-4f46-9a38-cdca059e8867@roeck-us.net>
In-Reply-To: <19c0ec82-59ce-4f46-9a38-cdca059e8867@roeck-us.net>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 29 Mar 2024 10:17:34 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7Po9B5WQMAUfB9jUmGAVit0+NiDbhV4jG5xKJUbWEBOw@mail.gmail.com>
Message-ID: <CAAhV-H7Po9B5WQMAUfB9jUmGAVit0+NiDbhV4jG5xKJUbWEBOw@mail.gmail.com>
Subject: Re: Kernel BUG with loongarch and CONFIG_KFENCE and CONFIG_DEBUG_SG
To: Guenter Roeck <linux@roeck-us.net>
Cc: Xi Ruoyao <xry111@xry111.site>, loongarch@lists.linux.dev, 
	WANG Xuerui <kernel@xen0n.name>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ED74/NW+";       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Guenter,

Thank you for your report, we find there are several kfence-related
problems, and we have solved part of them.
Link: https://github.com/chenhuacai/linux/commits/loongarch-next

Huacai

On Thu, Mar 28, 2024 at 7:39=E2=80=AFAM Guenter Roeck <linux@roeck-us.net> =
wrote:
>
> On Thu, Mar 28, 2024 at 03:33:03AM +0800, Xi Ruoyao wrote:
> > On Wed, 2024-03-27 at 12:11 -0700, Guenter Roeck wrote:
> > > Hi,
> > >
> > > when enabling both CONFIG_KFENCE and CONFIG_DEBUG_SG, I get the follo=
wing
> > > backtraces when running loongarch images in qemu.
> > >
> > > [    2.496257] kernel BUG at include/linux/scatterlist.h:187!
> > > ...
> > > [    2.501925] Call Trace:
> > > [    2.501950] [<9000000004ad59c4>] sg_init_one+0xac/0xc0
> > > [    2.502204] [<9000000004a438f8>] do_test_kpp+0x278/0x6e4
> > > [    2.502353] [<9000000004a43dd4>] alg_test_kpp+0x70/0xf4
> > > [    2.502494] [<9000000004a41b48>] alg_test+0x128/0x690
> > > [    2.502631] [<9000000004a3d898>] cryptomgr_test+0x20/0x40
> > > [    2.502775] [<90000000041b4508>] kthread+0x138/0x158
> > > [    2.502912] [<9000000004161c48>] ret_from_kernel_thread+0xc/0xa4
> > >
> > > The backtrace is always similar but not exactly the same. It is alway=
s
> > > triggered from cryptomgr_test, but not always from the same test.
> > >
> > > Analysis shows that with CONFIG_KFENCE active, the address returned f=
rom
> > > kmalloc() and friends is not always below vm_map_base. It is allocate=
d by
> > > kfence_alloc() which at least sometimes seems to get its memory from =
an
> > > address space above vm_map_base. This causes virt_addr_valid() to ret=
urn
> > > false for the affected objects.
> >
> > Oops, Xuerui has been haunted by some "random" kernel crashes only
> > occurring with CONFIG_KFENCE=3Dy for months but we weren't able to tria=
ge
> > the issue:
> >
> > https://github.com/loongson-community/discussions/issues/34
> >
> > Maybe the same issue or not.
> >
>
> Good question. I suspect it might at least be related.
>
> Maybe people can try the patch below. It seems to fix the probem for me.
> It might well be, though, that there are other instances in the code
> where the same or a similar check is needed.
>
> Thanks,
> Guenter
>
> ---
> diff --git a/arch/loongarch/mm/mmap.c b/arch/loongarch/mm/mmap.c
> index a9630a81b38a..89af7c12e8c0 100644
> --- a/arch/loongarch/mm/mmap.c
> +++ b/arch/loongarch/mm/mmap.c
> @@ -4,6 +4,7 @@
>   */
>  #include <linux/export.h>
>  #include <linux/io.h>
> +#include <linux/kfence.h>
>  #include <linux/memblock.h>
>  #include <linux/mm.h>
>  #include <linux/mman.h>
> @@ -111,6 +112,9 @@ int __virt_addr_valid(volatile void *kaddr)
>  {
>         unsigned long vaddr =3D (unsigned long)kaddr;
>
> +       if (is_kfence_address((void *)kaddr))
> +               return 1;
> +
>         if ((vaddr < PAGE_OFFSET) || (vaddr >=3D vm_map_base))
>                 return 0;
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7Po9B5WQMAUfB9jUmGAVit0%2BNiDbhV4jG5xKJUbWEBOw%40mail.gmai=
l.com.
