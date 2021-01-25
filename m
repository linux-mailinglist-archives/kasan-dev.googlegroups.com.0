Return-Path: <kasan-dev+bncBDV37XP3XYDRBW4CXOAAMGQE36I5MGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CBAC302538
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 14:02:25 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id t5sf173473vsq.22
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 05:02:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611579742; cv=pass;
        d=google.com; s=arc-20160816;
        b=K3naBD9v73fhoc1qTzY8uuhmT3XGY5m3u1qyUZsl+LIh0yAb3W380z0qgoH3lDJRg/
         vO9B/z71q45itArHNZHY6ptM1u2I6xpKur90VW3mrTBunBpKN/z2ny/cSkeR5sG7Elvv
         U/S6RQOTUqKIEE5MAIUkVHG91c35HB/GMfBZKiAYbCkOraX0Bb0ZgcEygac5zuS74miS
         9KJhwwDvq2EJBL9ttr12FV0ULzFYgKDNR9Y4yGF0SRxLPNDS3I8C3rlapNr4aI96S97R
         QCQFz6hwNsd+cqHlF6Si9PheF7RmAuS+0ZOMVs5Y2qIRGNvkYOIq+NLrrLjjSo9X88Dq
         QMoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=M2ews0bdUuKQ1MqFmViWikHOETT5Z0sKOiz8b909b6w=;
        b=ZsMqLjCFlykP1wJDNkFGmcBHXJ2AOawZoifwBEDpMec7hVfhkCw7KDakpziddPJsSM
         lDUpe0EGw9yWe8irXSRz3cfr7IDv+PgjuzDpueQcBF6sGlXxU0EPwKvHZvuKLqx7UrT/
         o8MN2TlVn5wfPiY7CEltOj9pZ8rYLV5+o+7kQWeF7WEULYSXtQ4YhCfQ5m2YBT/50xL4
         xoZhov6rE2GrC0ozQClP6+kcWe7SqRJVPm2g28Rt1PX6PTz8blgVFd3linlyn1iiIrvp
         aFHEZR8Rz/theb/XZXUWH0UzDww6t2vlfM36q0qv1KUxjOSu7NQULYt949hNYc9Hh93/
         7Ejg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M2ews0bdUuKQ1MqFmViWikHOETT5Z0sKOiz8b909b6w=;
        b=akL1cH9/cxq9wWu8/fhT3TPIhhtRnDZLB8W4/qSPNT84tOrRcv+riP5IKLma2l89se
         7KnTNsCiJMENBkWmqXiD9SKG3Z4renwjVWO0jqJ+BuXF8gHrTGaqWCTq8lYDgCHHtGXK
         ASt2NaBoXP4JxItrp2YDd4yBJvvQyTm8U5YRIigswcNCa82FC4bwgATgFVh33QTqFfWQ
         vN170N1lsbaiBg807wZZDnHPtCrJYdRcw8iMLDlEWYMUoaXlDSCDXG0dgXdAZX4zZJj9
         Mtsr/wubAHtLta9VBJ7ROl+fVWtrUXPoG0ht0vRUVXKWnLLubYKF2KbMiQTb4UPRr+Ns
         ZufQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M2ews0bdUuKQ1MqFmViWikHOETT5Z0sKOiz8b909b6w=;
        b=kYUcVEMZxj6o+rrcgjDsLs9Dq+Kf45+lcPBjWKGII6gD+9Mm/2ah8S8Lkkv4WFd4me
         p1JrKhPXqmaf63XF0MCxWIfCp1sT+jc9cWhFT6stY10Jsn+cggVV3ytadHikBxtij16V
         4tpZS6xw1kCrwBAJ1jL/BvozLtfvwFcMa5Kt5tJZ2RAKNOeTfzUXBrZpL0qSLxij7NkK
         jn2MqLQKQd3GlxgGLNW3iETiBNa9SIYJ+cP5OuUfOXpdTCahk8zwfX4OWEUjaJx4zFH1
         WZ/OuquMwRWcQpkw8slBF29SjTK+45h/WjHTeA9q80HaxeEmufRtNs8u1EeDXrLBw2Wl
         ZBcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qzvgA4dx4NrEvPpYWT7A/z4HzPRnQf65xvtX6CFXJJ+lnUT43
	yDmSVWkU0oxodwhTipHoCzg=
X-Google-Smtp-Source: ABdhPJwYd4WAktxatL7ABy6JoOeSktc+pVqPSRQpJ5jO2iL3FfBPjhM40Kdnu66XJ1HtazT9W+RBiA==
X-Received: by 2002:a67:7d01:: with SMTP id y1mr317680vsc.18.1611579740073;
        Mon, 25 Jan 2021 05:02:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e306:: with SMTP id j6ls1610450vsf.7.gmail; Mon, 25 Jan
 2021 05:02:19 -0800 (PST)
X-Received: by 2002:a67:5d41:: with SMTP id r62mr413412vsb.18.1611579739358;
        Mon, 25 Jan 2021 05:02:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611579739; cv=none;
        d=google.com; s=arc-20160816;
        b=tYiRAr0/kwt/BDHLBmAGce4cKrfJ1/hGJruO/ftG4sQDXi89m/9Wtb+jqJFfrsSQiS
         JIaI+7k4mAf3xFs3v81KvyPZLj82ckcTvREV8J+X8GUg+ZJrIqig+vlnI48Pz34RLI1+
         jD+XqqNIBh8q2hBtsLQwmMefSWYaebaVZimrqKKZnc6qBElyZuw4046z1jmKPfnyjuZu
         IHVod/VRY6uMBk0XVlXosAot43l10mFpa7twTi8AntErMs2MiBHCvcDM2Vtr40xpC65k
         wx7zSmW+nT7CYJOZiH82OCZpqk0ors4kc68aEg6NtRPuwyZBLWMCjXUFQX5THLcNzTww
         K9qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=5RpuWorZpeUrFktYMPbx1BE1XJ2XBefofvkizCyggQo=;
        b=LdQCK/2cmjp8aH3z0V+M2Vw2tZ2u4dMElqtJB7kqnOrgeJx9qLentnfPRXJqnQK2rC
         WKQG4zyBiLDapQtvKr7Xz9vr9sKY1GZiLtAaMwZBkUpsWByDNy2UrKCy79pq0iDBal2b
         NRj2FYuL9Mamj3q78FPzPa5ENfTpu1+aAVEmQBGFDNYYmALLkPDgQfjzg8fZ+ZwsYmzF
         JfKnWiltA36RHPRt6dxgOJTQErvLfzsloAXZXnYHk6KZT+Qpqr/pCC58zvqz5B5fbNJp
         qIMpWstIHq8yycFOy9ZEGvAjEkvsn6qgIKdx1qFA/it1nlkG8OH8eAxwDs7pwLx8d6Du
         VvMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l11si863324vkr.5.2021.01.25.05.02.19
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Jan 2021 05:02:19 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9A65411FB;
	Mon, 25 Jan 2021 05:02:18 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.45.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1EA8B3F66E;
	Mon, 25 Jan 2021 05:02:15 -0800 (PST)
Date: Mon, 25 Jan 2021 13:02:04 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [PATCH v4 1/3] arm64: Improve kernel address detection of
 __is_lm_address()
Message-ID: <20210125130204.GA4565@C02TD0UTHF1T.local>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210122155642.23187-2-vincenzo.frascino@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Vincenzo,

On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
> Currently, the __is_lm_address() check just masks out the top 12 bits
> of the address, but if they are 0, it still yields a true result.
> This has as a side effect that virt_addr_valid() returns true even for
> invalid virtual addresses (e.g. 0x0).
> 
> Improve the detection checking that it's actually a kernel address
> starting at PAGE_OFFSET.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Looking around, it seems that there are some existing uses of
virt_addr_valid() that expect it to reject addresses outside of the
TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.

Given that, I think we need something that's easy to backport to stable.

This patch itself looks fine, but it's not going to backport very far,
so I suspect we might need to write a preparatory patch that adds an
explicit range check to virt_addr_valid() which can be trivially
backported.

For this patch:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

> ---
>  arch/arm64/include/asm/memory.h | 6 ++++--
>  1 file changed, 4 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 18fce223b67b..99d7e1494aaa 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -247,9 +247,11 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  
>  
>  /*
> - * The linear kernel range starts at the bottom of the virtual address space.
> + * Check whether an arbitrary address is within the linear map, which
> + * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
> + * kernel's TTBR1 address range.
>   */
> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>  
>  #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
>  #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125130204.GA4565%40C02TD0UTHF1T.local.
