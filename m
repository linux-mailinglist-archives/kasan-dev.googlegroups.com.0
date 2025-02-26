Return-Path: <kasan-dev+bncBD7LZ45K3ECBBZ5E7S6QMGQE7RFMRDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 8335EA46040
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 14:08:57 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2fc2b258e82sf14528981a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 05:08:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740575336; cv=pass;
        d=google.com; s=arc-20240605;
        b=iuHaPKsq3mUjnD1OLa6a8ejW5eg9kiPxw8qrnr31EKmoAAVW5a+jKZV/iRwm5UKFV7
         cG7OOzzh2AoicgVimfbApNLZoBCzXIk5duoMo0/OESXfRmJg7cubLbqpqgX5ClTZ3m+6
         T0kq1fHIlLVrF0vlHDzsM40FZBe10paqcSscSu9sFo8s0G2Qhoreah9pNfZf7y5SYdbT
         TsCvKKT8jHSzHtdUYAU29eeS0uxk/t9VnFxByL/mKMZThNzpXhCYqzdxDYVham4Vz6hf
         YTeRzJI0RFiTGvFGA5yX60AQjlcBOEBWBiS/BBVm9bcuoy43sZo3T542z5SPwxHbkbq5
         +cmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HZwlZ+twApuoEa70/y20Pa/Y4zWmnWj8tl1nyYN/BaE=;
        fh=KD3ymtTwLgaLF64AMH3/abpdJvQcU5wDnlwZIleHk/E=;
        b=DsaVnnsjZo5lzLtYRL4i0+HmUcYrY3npQZxn7zjZn5gDtlvbMd1r1UJ8YzKFgLO7JE
         PB0CfRw3d0Ldi9RE+WToY/z9sRQRF6fayXgukPD478p45lN/h9/u08JX4Y83so5sEdr1
         T3oyeLf7+fMgecwltQx/ipYuZq/uNNUsH1F7ofFK3+xwSKgjhynX4tsEw5y8FxZzod85
         4+v9aNHgTYQhN+mere8u25XHK32CpIE0Rc/TlOdL76/2fyAYsKnhLZOCYm87zefxlA/J
         HGjxI48O6JGb5cKUwarps86M8x8EPA5ZJdVf8rCcEG7WZlY6SI5Hu7PkHVVM8vVXmlEb
         4UnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ME+RHoIL;
       spf=pass (google.com: domain of mingo@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740575336; x=1741180136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HZwlZ+twApuoEa70/y20Pa/Y4zWmnWj8tl1nyYN/BaE=;
        b=FwFkfS7hU1tnsiZLr1ZhIU0EfB/oS9G5JwzKWFCfTYSh40RiIZzJdNcsBu9DSuEmZU
         g3u4GEiYnPfJgD5vpkOkHY/3ad1UQu+kw1USEezgg/Vy5yZi+v2Ixzvsy4Ylf+Iib0j3
         uQQaj/j5AU5+rvX7lf2dibwGdcUCxze5hc35hLOV8zaDYH7FXNocw9b1LltK6ZtVNzGd
         VKSG7gAHNbFDT530ZywXhubyVOt+xplla/CDp3tMh2Nqvc2DTU+XS0GxTyFdisyRXE/c
         43eMj302Dt4+gQrCKyreRQ4OO4/zEKA33TPGx3IRfF3Wz7gXzkQCO6vNbNNKThl0K4V4
         jDyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740575336; x=1741180136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HZwlZ+twApuoEa70/y20Pa/Y4zWmnWj8tl1nyYN/BaE=;
        b=AfUqelLUetD5Z+7jx0Rj7/hg1JCFObx1rXCFmYMBt8S6JGYOSb+DoAGB4Y1wp0iO8R
         0wrqcRw/DHfQ+K748TWAYZQmD7q3VfTaNK/epmv89lXXPeKp9OiRO/IiAqGK+689OYGg
         uD1CuVjGsHsXsTccVZNGRiDag/MeVtShhdWOEGgIGGrj57Dz4Tei1KvHe5yRJMNMqbpW
         khNx3oGinco4/C0YvpEjWZCu1pZOKFewT7ABqcojoqlRN85fwsjsjNEQ93K1QHZnuAcY
         cXmvhZ0HYknyG09fMEns3bkz8r5YK0/eRpnRrvHk3WqAc0G1p3SJ0MItPZltqbdLY4hh
         zaBg==
X-Forwarded-Encrypted: i=2; AJvYcCWQ9vdW/y2yxqhHMMRMHmZCu5etsYuDqn5FeicdcftFaPuhCOg/jTqphchAe1gI52TBl0RbIw==@lfdr.de
X-Gm-Message-State: AOJu0Ywg5s1Wo+kN5yw+rcrSnX0wOqvXLzWJf1OXhKKgEh8XBtxSqQH0
	KHshWy3W4VDEimtzAHyXH6x8HHkMBJSSveHSbuF2sTvaK6uCHC+A
X-Google-Smtp-Source: AGHT+IHCcFj3xJZQjAzHvpPTlfumiU9YLbTf0XdKlmHRiYrORiM8H9LmZFb0Jubx8DMTQ5tFDGsqGw==
X-Received: by 2002:a17:90b:4d0d:b0:2f2:a664:df19 with SMTP id 98e67ed59e1d1-2fe7e2e0719mr5850670a91.7.1740575335484;
        Wed, 26 Feb 2025 05:08:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGz7nZFGuOdqSjrF6vjr6gclC61nXFdkmiXT6dVI5iYTw==
Received: by 2002:a17:90b:274c:b0:2f8:3555:13c3 with SMTP id
 98e67ed59e1d1-2fe7ec64f1els925711a91.2.-pod-prod-09-us; Wed, 26 Feb 2025
 05:08:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7QDop8dhWsauvE3UtdCnczlRpIcOi1oI3HBlCdPexfRxdHboeyxJFbs6zm4tfjLRpnyo/6ZFP+Po=@googlegroups.com
X-Received: by 2002:a17:90b:350e:b0:2fa:20f4:d27c with SMTP id 98e67ed59e1d1-2fe7e3899d4mr4420404a91.34.1740575334145;
        Wed, 26 Feb 2025 05:08:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740575334; cv=none;
        d=google.com; s=arc-20240605;
        b=OuS8SP/4z1VjjceVqlST0g0cT+pJ8GM8rFObg4GDzggwdJyy6DuKJV5cn8T6UDgM6p
         aMZEc2WynJj3mULLEzPHVmjwEv0JL6Hfw7mbjcDzPytPDWs8d1PtmtCQ1ol2YsmDoYeq
         hrOj3z+GUZ/XQp9On/Vc4JV+MDBygKQF1Inftez1cO99VkhH/klyRe0OVs0FtPsIeqEw
         21bKKfVEZfs0ydS4o6DynXADiQXJ0mteH5tdBlB5w/eCNnKxpRtDHxv8bpietveApkfe
         Z4RPvxeOTRq8rXD3INwjgzqogjDcN8Hy5H98xOXA3AyktmGjkUpGkcNV6ZmbNo+9Y5PT
         Zheg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ffUtlDgn+1104ARBjRrukGIDGUi8geC9/KGM3iC88r8=;
        fh=dFKwGhGEYa4oO6IlyO4Y3VT4ZhmkRdAhr9u8S/RFqSs=;
        b=OuENzqj9BXH0xnNMUKSpLYKXCOzcXrAvC0/RaZa3L6Fs/nW5vvNICNBmwae+bSUJ8p
         clTo+Yph+lYNt5k0NfN8wWADWLIWsAduksAGZcXLdGPd8rTi0UHU2PBlVjsLjX80OpA+
         xUitf3/DlB6bipSeNnf3Bc08vcywV4d/OopgnuAAIh3WC5N8LvAATZwGSvh4uyFB3+3e
         IZyUKuAemFJj7yACrAZTlLbBxd1lJ/g4PrUuvKCjeZAacGSlOq8lsgnaERwNCWGbK/wx
         PelmStQvdZt3x9tnrqLW/Fsy51GDwenNgRgaGn+xt9aUMMCiVqD1lOMGcA88VcBiWhvb
         ihxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ME+RHoIL;
       spf=pass (google.com: domain of mingo@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04::f03c:95ff:fe5e:7468])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fe6cf9555asi224647a91.0.2025.02.26.05.08.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 05:08:54 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) client-ip=2600:3c04::f03c:95ff:fe5e:7468;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 56AC56121C;
	Wed, 26 Feb 2025 13:08:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B4FF9C4CED6;
	Wed, 26 Feb 2025 13:08:50 +0000 (UTC)
Date: Wed, 26 Feb 2025 14:08:37 +0100
From: "'Ingo Molnar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Benjamin Berg <benjamin@sipsolutions.net>
Cc: linux-arch@vger.kernel.org, linux-um@lists.infradead.org,
	x86@kernel.org, briannorris@chromium.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Benjamin Berg <benjamin.berg@intel.com>
Subject: Re: [PATCH 3/3] x86: avoid copying dynamic FP state from init_task
Message-ID: <Z78SVdv5YKie-Mcp@gmail.com>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
 <20241217202745.1402932-4-benjamin@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241217202745.1402932-4-benjamin@sipsolutions.net>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ME+RHoIL;       spf=pass
 (google.com: domain of mingo@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468
 as permitted sender) smtp.mailfrom=mingo@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ingo Molnar <mingo@kernel.org>
Reply-To: Ingo Molnar <mingo@kernel.org>
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


* Benjamin Berg <benjamin@sipsolutions.net> wrote:

> From: Benjamin Berg <benjamin.berg@intel.com>
> 
> The init_task instance of struct task_struct is statically allocated and
> may not contain the full FP state for userspace. As such, limit the copy
> to the valid area of init_task and fill the rest with zero.
> 
> Note that the FP state is only needed for userspace, and as such it is
> entirely reasonable for init_task to not contain parts of it.
> 
> Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
> Fixes: 5aaeb5c01c5b ("x86/fpu, sched: Introduce CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT and use it on x86")
> ---
>  arch/x86/kernel/process.c | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/x86/kernel/process.c b/arch/x86/kernel/process.c
> index f63f8fd00a91..1be45fe70cad 100644
> --- a/arch/x86/kernel/process.c
> +++ b/arch/x86/kernel/process.c
> @@ -92,7 +92,15 @@ EXPORT_PER_CPU_SYMBOL_GPL(__tss_limit_invalid);
>   */
>  int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
>  {
> -	memcpy(dst, src, arch_task_struct_size);
> +	/* init_task is not dynamically sized (incomplete FPU state) */
> +	if (unlikely(src == &init_task)) {
> +		memcpy(dst, src, sizeof(init_task));
> +		memset((void *)dst + sizeof(init_task), 0,
> +		       arch_task_struct_size - sizeof(init_task));
> +	} else {
> +		memcpy(dst, src, arch_task_struct_size);

Note that this patch, while it still applies cleanly, crashes/hangs the 
x86-64 defconfig kernel bootup in the early boot phase in a KVM guest 
bootup.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z78SVdv5YKie-Mcp%40gmail.com.
