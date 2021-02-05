Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLWN6WAAMGQE7EUJFOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D3F3310D3C
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:27 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id dj13sf5231419qvb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539566; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDdnSChZ5n02JaSRuY/joFVewQjtChEjrEv1ZwYEK0TuROhc/HUmd5r7QQBh6WuW/f
         cQkv/D+bbHDgjZTJzGjq1/R75W6RdnZdTmBiNA3m891rbOH2+ezDGI5LN5vJiLOG1eFF
         z010MS9OY8zkYsfOL4+wEIVhmgXAPRzW3DUgjQLFHPIyFgE69g2w2aSeyLD3UUY1v1tN
         vFsms5FCIHykpNXn2kHhoeEl47SNstzkS7mvldFN2Yf3UZmqxj/7e0vVfbvEx0gKKfAh
         jrq38OAicaLkXy6XIh6SjFr9nlL8/CMxI4qc0sPzEV0sXU/8D327Qnc/38tjHcBx7vHW
         b5Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fy8CuOZ1d7SFjuw0wLicJbPfSk8GZqRyqDvApxRFaZU=;
        b=uSKIwKbjYOOTrgAvGIk/Eg4BAVczxSgDG+2siFIFpeZyaDdawFuLzLmV4/LYr5j5qn
         VaV1ekIO9Ehlm8RyWKCyngpSdJ8t5r1g9PQkgUSbY6ApHzP/rYqWc0RsqgYamsqsUQp8
         DSqK1ETgxbnjwrrXtqxd+jMxbk0eXAhgDCvCISGDL0ugl53jauW0sDAIAgWETqeHlvgq
         3cyoP2fIcqtrOCwaSHpEU7Acp45x8D8yZxXKncbiY9yuISrwf6DlkJsR+Vl4SPMfynxR
         EN6eFbCbcBIKpfrrHlKqccihE5FORmb1nrruSihot379XZKAl9DYfqXp+d/WXwf9+4zZ
         4ocA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fy8CuOZ1d7SFjuw0wLicJbPfSk8GZqRyqDvApxRFaZU=;
        b=s5jdE8HIpl56IMkHDXjooGmYLuOUnWjcUJPMG/vvTgx2GivHXU+BEnw89blq9r75dj
         wXnzR3YugZhZ7chxb9MldDgzv934duzC9p8LFiGbkPs1/I07rntZnIBExN/CyTYzsFt7
         FxV5VeIfeW4QjDGkvFlt6b+tYx+kypCmL6Hnu1AhFMftD8ti9U1lYnLfQDpfaEbvxDCE
         TgqkyB6IDm1vSm58k7GRk+EfqN4V8Ok+Awupmf4TS0BS70h3iIzCbcOvOfrquCyh/brb
         BQUPWE6xyLvAiegOVYK/9Io6T8dolqlrYcXkXdEzd3jmw4UlmE7JgZ7guvF03hwaW33T
         Ns6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fy8CuOZ1d7SFjuw0wLicJbPfSk8GZqRyqDvApxRFaZU=;
        b=E+IbZhBXR5BQJiyBjcqn9qJQ5zM/401c1oe44+Y0meQlmJ8J8Ik/H9bywfedUFoM90
         NQGp/8JRSodrtTretSSyHXyvOxl8CLwp2VlJaldfm/0Tm6g8j2L5njfBu4hHp1UIX7NZ
         BVHx1KA6BwnzzgW/MR2cKwnQ0xcMFTbDGKijBrLoWsUl+H5y1KJOHhRsRMriOAhJbJx2
         bdeu4yhcoYO2sB0Ef9Fs6CEL9pic7j1vU50CxBKNbTf49bKtMhUTgeVLhQ0Cs9lageQ2
         U07/ds+25jhtLymsJCfNgm1CHY+ga2UTKJfd3x/71ALd2gFcUxgKzvVIVsl3QoSJ1str
         qfkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RYHQjkytv6S+6XL+Ff3Q57gUKLQZ1sqSr9+Pr233InA3hUXxz
	O576CAV8gDJFi4byBMmsY3s=
X-Google-Smtp-Source: ABdhPJwZt63GO6nQl07p9FzDVTB7Kju8JHoY+Lzsmt6QSEg/aVVHeT8UE6SYDo5J3v8tpuGkFb8LXQ==
X-Received: by 2002:a37:6351:: with SMTP id x78mr4820926qkb.180.1612539566413;
        Fri, 05 Feb 2021 07:39:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:758a:: with SMTP id s10ls3608910qtq.2.gmail; Fri, 05 Feb
 2021 07:39:26 -0800 (PST)
X-Received: by 2002:ac8:128d:: with SMTP id y13mr4660377qti.153.1612539565896;
        Fri, 05 Feb 2021 07:39:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539565; cv=none;
        d=google.com; s=arc-20160816;
        b=yYjtTe50u57YKrIYRdAwImnPNg7ffUDMqmsVRZx94/RlzWi+a7n26d55XkwIyH1P16
         XlTXDPgUzyPWqGBCo3npn70pHNa8M9YJrcd4Ze+tscxUVhEuzNk3I6dKG9ag5jYzbDTT
         FWm+Gpns8vrFPIiWxFe3+E+fK4609Rc0d/pJqcbt/c4ZLh8wYZX413sfN/EiMQ7E2cPj
         Ok0bfGFUJqyIq7/hoZItzZFsjQI+ePSlrcD9u+GL+7c/uxGiAfAFV8Y/HQ+SuKiLjHYU
         WmIudTmNp7Szm8T5YaWZdLX9+7L3UnBe9V1TW1h/b2aQnMcx1/D7aGxnDMxBuFLWpFHJ
         zpnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=zGMiZxfFIbdOBeOk+kEZPDpdD7ZCO7bf9IU/lMvS4hg=;
        b=SsNJDlqYJb8d9fIGpgv2I+2LKsZRragOQ0QuyxDNt0logxNQiavaZo/RjWbYbxOfK2
         KVdDDCkgoeX4fdQY3rRqwB2TANMsn4GwavCBMx1SgRYGQhml+koRo5NyY1O0TLP7YQfk
         CEsk00BrJYTX9yB8kEG9s3AXe54GAsBmxGZBIfJ1wIQQQYQtW6OMtDsuaRBwOwsQ/9Rm
         LbDjrTyVhmdV6nQMpwxLjAP+zTUEnnYI2xkoj+jNErUwWBgtcNAgj+BQJf1wKTi6HMon
         LKQ3fZMmCFi6f038yj3U+ji4PXRS2js1t8zy3L6oRz0nZ16/Ao4RFx1nz05Ni4WnWX6E
         nuQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j40si854340qtk.2.2021.02.05.07.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6A7DE650F0;
	Fri,  5 Feb 2021 15:39:22 +0000 (UTC)
Date: Fri, 5 Feb 2021 15:39:19 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v11 4/5] arm64: mte: Enable async tag check fault
Message-ID: <20210205153918.GA12697@gaia>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210130165225.54047-5-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Jan 30, 2021 at 04:52:24PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 92078e1eb627..7763ac1f2917 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -182,6 +182,37 @@ bool mte_report_once(void)
>  	return READ_ONCE(report_fault_once);
>  }
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1(void)
> +{
> +	u64 tfsr_el1;
> +
> +	if (!system_supports_mte())
> +		return;
> +
> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +
> +	/*
> +	 * The kernel should never trigger an asynchronous fault on a
> +	 * TTBR0 address, so we should never see TF0 set.
> +	 * For futexes we disable checks via PSTATE.TCO.
> +	 */
> +	WARN_ONCE(tfsr_el1 & SYS_TFSR_EL1_TF0,
> +		  "Kernel async tag fault on TTBR0 address");

Sorry, I got confused when I suggested this warning. If the user is
running in async mode, the TFSR_EL1.TF0 bit may be set by
copy_mount_options(), strncpy_from_user() which rely on an actual fault
happening (not the case with asynchronous where only a bit is set). With
the user MTE support, we never report asynchronous faults caused by the
kernel on user addresses as we can't easily track them. So this warning
may be triggered on correctly functioning kernel/user.

> +
> +	if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
> +		/*
> +		 * Note: isb() is not required after this direct write
> +		 * because there is no indirect read subsequent to it
> +		 * (per ARM DDI 0487F.c table D13-1).
> +		 */
> +		write_sysreg_s(0, SYS_TFSR_EL1);

Zeroing the whole register is still fine, we don't care about the TF0
bit anyway.

> +
> +		kasan_report_async();
> +	}
> +}
> +#endif

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210205153918.GA12697%40gaia.
