Return-Path: <kasan-dev+bncBDYNJBOFRECBBDHWRLYQKGQEFKZFYNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 323C914166F
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 09:00:13 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 126sf6472692ljj.10
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 00:00:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579334412; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOPWxKnRIQVuP8lWUudr+6zlYP8wHTic18QrylDTzxE3w54SfPP4/IfzZGP+Mf5jWS
         Q8SU0MP6KXxFSUsrRl+5Xnv9mFi7xzrT2cvtW3eGn1kgTCcejSulOQPw+jGsay9KRjiM
         ng70Kmofnn9UXBCMFs5AX9C4rOk8IqpgI0ljr0qpqHi2UE2h/YUpYpb6+uVxrjBEJAj/
         9TGPw6te8pujySG/jbbui9GA+d/dYlQJ4TCdCz1MdFABwIbWv3/Vs7r44HP4i9A3Y5aT
         MsYR6brd9JaJ/XW4IO2bYnoVRvRyWL+TlRluXd5X7fR/hpp2griLWL7HAsmP+pBwa8FO
         +oGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4wbzpVVmMPAX0sDZsEKMDnFB4eWQtmjEiUIMJ8olDQ8=;
        b=sI6fHEOa5IMtTizRa6daqNLqk4YdmDd9u2RbecIT/G8BtjGG2HqJE7gH6uY3bss9ci
         XOK0S7ff3q/XBYb6t3x/PEG1OIExZFNWAFn44hmfWdQyIPwU17kXwA8LYaelvGakxkRd
         YaI2tR1GJDzN/922hvNZh/Rbz57WtDqrZ7HUX93MQ6tzgQ95aPlFB2cZ1a9FzmtyzjV6
         M8sQmzAviLTyafHl0xaRMp7p+Y0aqZT2S9DN+pFRmcXkVd8CSlnyAGZ+/5iIIqWvgEet
         UgV76una+JtneysW1hQGFczMEldENvAet+Kw321xJo+87yKl/DTnqdXv6zJyR2fxsJKd
         EoNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="vG/c8xAM";
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4wbzpVVmMPAX0sDZsEKMDnFB4eWQtmjEiUIMJ8olDQ8=;
        b=Lg1kR467bLOFHVJsPyrpdDA8VGDJzRxnBx7iwRUL71tNJf6Yu/mwtEZZLd2wDSRfrh
         6Li2itY0PHCAR23HRGylT9XEm53350CVOCPD5766v3lfOoV3+0j7Bu9gUwYSujvYjN/o
         xrVtX+iRfXuYp4WhMIe9TU6R38dGlXgDIl29lyIX0r97Fk1mg053+nzA7TxI+5z4DmyO
         B8+ON1not9x2GztzCxcCcKAr/QN93yTVdbQQxJH3BNtaqzw4vZqol02IuP4lyo8t2Lot
         FTscEzyBgqylF2NkJycG79iYEZT1lhUsaX8dmtPLg/UIPPm+r0OigzTghVjNkwrby7Y7
         5Ozg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4wbzpVVmMPAX0sDZsEKMDnFB4eWQtmjEiUIMJ8olDQ8=;
        b=NKcKYxmEMUgdFZYt6Q2DrrOmvscvL2HdIOOYL+KkpgQaMwjfcqRlEV+DOUI0gR2bJO
         9vxD2Cw1TQ20jDp2MejPpgNpS5bf7oDj+IVotFpsAbquBcO0p/8YRUtrdIOyFMdwhRIY
         AOvn0BQVhLC95lmfKBJlWiWwFcgCVYYL+zJMU4KAEHCj57OSWuyiIVUU/+c/H6o//Qp2
         FRcE/nKnXx5PVtOur9THom9IK27dQf5QSlpO1FY5PRnzDH7P6p3mwPnpLXMn6xbwcz1p
         4AKKNhF01gK55eUMGw9Ph8VuQ62w6ap2nM/qvod5uTWp1fDaOYYd6v+7U1izojsEF78F
         mmfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwKuKnRk64QEvc4uSsOMdH15YJfb0Jf01D515PeWrrf3HBXcZw
	dK6cOLP9y87+STOcSZ7H9q4=
X-Google-Smtp-Source: APXvYqzfPVh4SE1Byd+P8NoxbDgyhJazDvTFfKexj41BO6l56aIFncFacFKxbO8awaNniOpovRlpgQ==
X-Received: by 2002:a05:651c:20a:: with SMTP id y10mr7392978ljn.216.1579334412511;
        Sat, 18 Jan 2020 00:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5219:: with SMTP id a25ls2649047lfl.16.gmail; Sat, 18
 Jan 2020 00:00:11 -0800 (PST)
X-Received: by 2002:a19:740a:: with SMTP id v10mr6349182lfe.65.1579334411810;
        Sat, 18 Jan 2020 00:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579334411; cv=none;
        d=google.com; s=arc-20160816;
        b=vHfFOGR1JWgUeN5axSxodklV6HH2hxppviHA+X0apk8DYit1jGgIvxxaYGrI26oLHS
         Bkoz5buToS8XP9nB3lXL+954yfxoEH/cohH4Crx0x9whJloZZCLkKoks8YuaIqgzXT59
         CrVwvgBenVG56eQIUQcgw3n71/vscVYGS3HTJrS4M9wl1ZnIkbLwCKgV900Tkpt8Ks7g
         uxSMJEX92HM4wcPXaMmgsX4AoY8a8XjFoD1au5YN2l6FT+ju+HNe2F+XZ/7pYr4JG/iF
         rLQhG42U0i5uDlLyqfmgHf7ZzyAQ7jLzceMjjhtY77nOJoNt6qtHs08pDWw4SADMPzFt
         SGjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WFOEOXqnCDTTcDQn4El+71G/5ufyH8CwcIjRAHLYoAg=;
        b=aYGMiVww/xpqdmveEACnVzGbQATdk6BFK3gQoWBUY9lq7iB5XgR8bwN4N2kYD5EoM9
         eBs/ZMYHoWDljXJnK4T7KI6kJM3XTNHgFh9i+RxaHxu80qKB3vzbeKEva/uoLNNbSD5y
         1X7LNGVroNv6oPJZgkPcFXOd4akYarXtYT3oObEteosvNXViXtU9W7tbVRuHJAvrRfRD
         Yg6eqbeyK4bffUPh3sTEG6UqiSmZaILHb7PF5LWBuM/oJohNjRhAGJ8bMYjrxYo42DnN
         3XA0fEmA6q/kOpfHig7yffxZ1elWGEe/lFwxXoQRsF8gBjqmLjxEQpY3mgkyj7y2aj2l
         GU0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="vG/c8xAM";
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id p20si1449852lji.1.2020.01.18.00.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 00:00:11 -0800 (PST)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id z3so24764900wru.3
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 00:00:11 -0800 (PST)
X-Received: by 2002:adf:e3c1:: with SMTP id k1mr7276173wrm.151.1579334411045;
 Sat, 18 Jan 2020 00:00:11 -0800 (PST)
MIME-Version: 1.0
References: <20200118063022.21743-1-cai@lca.pw>
In-Reply-To: <20200118063022.21743-1-cai@lca.pw>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Sat, 18 Jan 2020 09:00:04 +0100
Message-ID: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
To: Qian Cai <cai@lca.pw>
Cc: Ard Biesheuvel <ardb@kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="vG/c8xAM";       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
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

On Sat, 18 Jan 2020 at 07:30, Qian Cai <cai@lca.pw> wrote:
>
> The commit 698294704573 ("efi/x86: Split SetVirtualAddresMap() wrappers
> into 32 and 64 bit versions") introduced a KASAN error during boot,
>
>  BUG: KASAN: user-memory-access in efi_set_virtual_address_map+0x4d3/0x574
>  Read of size 8 at addr 00000000788fee50 by task swapper/0/0
>
>  Hardware name: HP ProLiant XL450 Gen9 Server/ProLiant XL450 Gen9
>  Server, BIOS U21 05/05/2016
>  Call Trace:
>   dump_stack+0xa0/0xea
>   __kasan_report.cold.8+0xb0/0xc0
>   kasan_report+0x12/0x20
>   __asan_load8+0x71/0xa0
>   efi_set_virtual_address_map+0x4d3/0x574
>   efi_enter_virtual_mode+0x5f3/0x64e
>   start_kernel+0x53a/0x5dc
>   x86_64_start_reservations+0x24/0x26
>   x86_64_start_kernel+0xf4/0xfb
>   secondary_startup_64+0xb6/0xc0
>
> It points to this line,
>
> status = efi_call(efi.systab->runtime->set_virtual_address_map,
>
> efi.systab->runtime's address is 00000000788fee18 which is an address in
> EFI runtime service and does not have a KASAN shadow page. Fix it by
> doing a copy_from_user() first instead.
>

Can't we just use READ_ONCE_NOCHECK() instead?

> Fixes: 698294704573 ("efi/x86: Split SetVirtualAddresMap() wrappers into 32 and 64 bit versions")
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>  arch/x86/platform/efi/efi_64.c | 9 ++++++---
>  1 file changed, 6 insertions(+), 3 deletions(-)
>
> diff --git a/arch/x86/platform/efi/efi_64.c b/arch/x86/platform/efi/efi_64.c
> index 515eab388b56..d6712c9cb9d8 100644
> --- a/arch/x86/platform/efi/efi_64.c
> +++ b/arch/x86/platform/efi/efi_64.c
> @@ -1023,6 +1023,7 @@ efi_status_t __init efi_set_virtual_address_map(unsigned long memory_map_size,
>                                                 u32 descriptor_version,
>                                                 efi_memory_desc_t *virtual_map)
>  {
> +       efi_runtime_services_t runtime;
>         efi_status_t status;
>         unsigned long flags;
>         pgd_t *save_pgd = NULL;
> @@ -1041,13 +1042,15 @@ efi_status_t __init efi_set_virtual_address_map(unsigned long memory_map_size,
>                 efi_switch_mm(&efi_mm);
>         }
>
> +       if (copy_from_user(&runtime, efi.systab->runtime, sizeof(runtime)))
> +               return EFI_ABORTED;
> +
>         kernel_fpu_begin();
>
>         /* Disable interrupts around EFI calls: */
>         local_irq_save(flags);
> -       status = efi_call(efi.systab->runtime->set_virtual_address_map,
> -                         memory_map_size, descriptor_size,
> -                         descriptor_version, virtual_map);
> +       status = efi_call(runtime.set_virtual_address_map, memory_map_size,
> +                         descriptor_size, descriptor_version, virtual_map);
>         local_irq_restore(flags);
>
>         kernel_fpu_end();
> --
> 2.21.0 (Apple Git-122.2)
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu8WBSsG2e8bVpARcwNBrGtMLzUA%2BbbikHymrZsNQE6wvw%40mail.gmail.com.
