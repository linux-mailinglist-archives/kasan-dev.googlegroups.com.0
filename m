Return-Path: <kasan-dev+bncBCT4XGV33UIBB7VBRWUAMGQE62L465Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id A1A117A0CB7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 20:29:19 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-412136f4706sf12738221cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 11:29:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694716158; cv=pass;
        d=google.com; s=arc-20160816;
        b=pgoCUO1kJRskt6kZGn3g/Ei7Sg+Cv4oXOrsaxbBlPYDaBzP2jWTum0+rP9nBurP2J2
         4X373fOasnfTdbqLg+HfiLIi8aDxl6bbUFbp3cKGw+Y/q0RjBMHjb3p4zSJn6VcZJ70j
         AMqPO104efMv88UqAhLGF5WMat3M6/s5iepa9LnJ7uw1dx1Bafr0EHhu32B300zeI4l+
         3sK2sAppNBULOGXwYpQW5/UTz6RjwHAQrOmNk6+FlVQY0YcJEHhu1yBo8zOLrlWIVprK
         3/PeU1gRr/WBwM728GoljE2rUNMvoJ8hW0mOcEDYbOYbRM0exaPb+dkoGzY4hbQwwiru
         zXmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=vKvVUoYbQ4/bQWot7J1cGr8OnNHWiAfRszw5AEsAqUQ=;
        fh=vLZiHvNyRixTsWRMQQEoUIZneGxtl/+HKmDqv68ZeyE=;
        b=XzGIJrwzJ8loOs6nt2XMZhthHA0bu7SLw7nrumPm2h+Kcz37dF+9xLE9ucdl9DR8+r
         5jLoaMsGm7T/VlA+tyIpatiSXZuDm8jB635ptDZhQQBVJoo3xPwmhKBTKX47v3YgOGsZ
         m5ewW8nMpjL+bkqiIGXtAnlwNFvBKOkaonvH0j5jgAFNTi2nmkHUY5cxziESMUJtf5zn
         hWVRQ4xfzzgobl+fcE43fdC9HxsPCPY/07Z9OzhsW2OfjUPUW4CwA1/bHhC6SarID2rv
         fUjjxyUxlae9kcj6KlabG2TUGx1TvFbTj0c6CVf7wW6Za3HS3/Hf+INJyjaK6N+1F1Ec
         kX/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=k8uDcAI3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694716158; x=1695320958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vKvVUoYbQ4/bQWot7J1cGr8OnNHWiAfRszw5AEsAqUQ=;
        b=KZiGv1Rpa0ZffUCeecuwPHKtmmXrTIgfLCHcL1HtM6YI7YLjSQaYbJgZ5VuPLEEIqJ
         f1UnePlop7LY1bjfMMSUQ0lxejSiqnEmZmTW/DGxjh+Vh3feAYW4aSMnen/20p44dXVr
         CXhhjUfZtk5QyJJuGydyh6xOXTX1VSGXs7OY6qcBLktFDDMH0vY7WL+yiIgSjSqbvt+2
         hxvxftn6MS4PSz5kyIxKa1BpWQGE/zd0G6XqGthbMsH2NBJh/RVn1EOj+x/J8IFhfspF
         lCr2qQb3k/bk+ktK2SWmhdz+d0ToPzzHzGzgM72cL7JjX2XWWuvpp90WXmd6Bq4w8cvt
         M3rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694716158; x=1695320958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vKvVUoYbQ4/bQWot7J1cGr8OnNHWiAfRszw5AEsAqUQ=;
        b=Td8QVJPfKcreg6LJS7Qbav2j4V7/eosaByk3AJSIhMl+P84xkOgaJd26iiHVWNC3BK
         k642SkzBzoZm+9PbJCwoGhxoTy7CSHr2VHDHUV6M5+XIHLDFKXcStKGtpinNIOH3hC3d
         g4HtDeCYsHnMiJYwkmma4ikQrzTRCxIq+CT5eRhXu2adGPyzf0cV+ypWoLhPu6gLReNJ
         tTQyfjN+80jrFxtM1ufP/Z624ZeVVC9dchFDGdoIWwat+5Iibtih58se+8kGkDRHHmdD
         4jezp4I/sZr67pwYEbjPP4oYGB9CtOjErN0Gg+fcr4fdhymTsxWI29nExAo5HNjXUXpA
         JO2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzfUaTeUUtt+5i1AL2PFPVyPmX18icW9RBjUBAVwja8HbylV7WZ
	n3D9ytcwLxKR5hQP33P91i4=
X-Google-Smtp-Source: AGHT+IFofSxeQR8kuZEcjohFT15qqcDj6ehAu43g0vOHoIYpTw9k450ntYD8nhTx22ujqFZHYmMvtQ==
X-Received: by 2002:a05:622a:1917:b0:403:ed26:4083 with SMTP id w23-20020a05622a191700b00403ed264083mr8503197qtc.61.1694716158433;
        Thu, 14 Sep 2023 11:29:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5507:0:b0:411:f89f:d135 with SMTP id j7-20020ac85507000000b00411f89fd135ls1182299qtq.1.-pod-prod-01-us;
 Thu, 14 Sep 2023 11:29:17 -0700 (PDT)
X-Received: by 2002:a1f:c806:0:b0:495:ec90:997e with SMTP id y6-20020a1fc806000000b00495ec90997emr6255425vkf.7.1694716157599;
        Thu, 14 Sep 2023 11:29:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694716157; cv=none;
        d=google.com; s=arc-20160816;
        b=nJrx1h0PeENLzyifykeKP/vCwZbWL3qBwQXXQm8R2OeuJhdhmn+dJ3sUT3ay4NQ7/C
         KdhqOLi+bzgEXebzPbBtYA+A8QvfDe4sr2MrbJ2TWT1+sHApzSXM1hywr6o2CQJ5cr5I
         hRx5smbEQtm9erTBu9tDd989iO4mh6iEJKaa+FU7hRWdGau2gaw6FDCSrgLCWs6IuxFC
         xHFrHg71g2zGy5GXXE/CDllZV0CT1pVGkdHKTtAGnqOEV5p1MPvXIIJPWKbzMP1zdyu8
         flK8DLLj0zmmAbUGiNkALMY3e8ADqSwR/fnAsbdT6HB8e05SUhetpMh+CuNQUS2HzNgZ
         MC6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6eRAg4BOSXhzdaCM4oFAMYBsORYMTL2ICOv9GCq6ZaA=;
        fh=vLZiHvNyRixTsWRMQQEoUIZneGxtl/+HKmDqv68ZeyE=;
        b=Qc6Sp0SoFGT/hPZgrFxi4rzE/+tTZEEuIPWiIzRPFJhQ7DRYTDP2wCt5g5wi9EqKQD
         aPfZcKIdQoUgoyC5EzaU2kRPnZSWzlxcsnVqgi5aeQznnm3aHumOH7hXjrk57e7fKmIX
         aQMWl/Cxto4C1fwq4UcE111/QfbOmzy9xbYCGa6dFai4EpBf0x0dvR5dtRS3lPcSEeSC
         e2dsBrLF25DJ53Sh+/sWbhEOKJTjb6qlbDWGVhd7V2sLNBtTfdiLVaUNF8pxYhD0BpPY
         AagR7BYHyuwB1vEk/mq2Opyinrq5LoAni7DJf1ClpjiipxTx92U+E9MtF+KYPyZddZ6F
         2VPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=k8uDcAI3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 139-20020a1f1791000000b0048d29aa0861si454234vkx.1.2023.09.14.11.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Sep 2023 11:29:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E656861DB4;
	Thu, 14 Sep 2023 18:29:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9921C433C8;
	Thu, 14 Sep 2023 18:29:15 +0000 (UTC)
Date: Thu, 14 Sep 2023 11:29:15 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Haibo Li <haibo.li@mediatek.com>
Cc: <linux-kernel@vger.kernel.org>, <xiaoming.yu@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Matthias Brugger <matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
 <angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
 <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is
 illegal
Message-Id: <20230914112915.81f55863c0450195b4ed604a@linux-foundation.org>
In-Reply-To: <20230914080833.50026-1-haibo.li@mediatek.com>
References: <20230914080833.50026-1-haibo.li@mediatek.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=k8uDcAI3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 14 Sep 2023 16:08:33 +0800 Haibo Li <haibo.li@mediatek.com> wrote:

> when the input address is illegal,the corresponding shadow address
> from kasan_mem_to_shadow may have no mapping in mmu table.
> Access such shadow address causes kernel oops.
> Here is a sample about oops on arm64(VA 39bit) with KASAN_SW_TAGS on:
> 
> [ffffffb80aaaaaaa] pgd=000000005d3ce003, p4d=000000005d3ce003,
>     pud=000000005d3ce003, pmd=0000000000000000
> Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
> Hardware name: linux,dummy-virt (DT)
> pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
> pc : __hwasan_load8_noabort+0x5c/0x90
> lr : do_ib_ob+0xf4/0x110
> ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
> The problem is reading invalid shadow in kasan_check_range.
> 
> The generic kasan also has similar oops.
> 
> To fix it,check shadow address by reading it with no fault.
> 
> After this patch,KASAN is able to report invalid memory access
> for this case.
> 

Thanks.

> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -304,8 +304,17 @@ static __always_inline bool addr_has_metadata(const void *addr)
>  #ifdef __HAVE_ARCH_SHADOW_MAP
>  	return (kasan_mem_to_shadow((void *)addr) != NULL);
>  #else
> -	return (kasan_reset_tag(addr) >=
> -		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> +	u8 *shadow, shadow_val;
> +
> +	if (kasan_reset_tag(addr) <
> +		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))
> +		return false;
> +	/* use read with nofault to check whether the shadow is accessible */
> +	shadow = kasan_mem_to_shadow((void *)addr);
> +	__get_kernel_nofault(&shadow_val, shadow, u8, fault);
> +	return true;
> +fault:
> +	return false;
>  #endif
>  }

Are we able to identify a Fixes: target for this? 
9d7b7dd946924de43021f57a8bee122ff0744d93 ("kasan: split out
print_report from __kasan_report") altered the code but I expect the
bug was present before that commit.

Seems this bug has been there for over a year.  Can you suggest why it
has been discovered after such a lengthy time?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230914112915.81f55863c0450195b4ed604a%40linux-foundation.org.
