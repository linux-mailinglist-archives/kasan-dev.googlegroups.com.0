Return-Path: <kasan-dev+bncBDDL3KWR4EBRBGFOR35QKGQECUGTNKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5243E26E1A5
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:04:26 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id c197sf1797652pfb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:04:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362265; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFGLh02xgYdwefYkDB6D/ig0XffVBPZPYw+ZXVy26sDlpEIhCCUJ6kyRgkr/MmjFqp
         /Ws2UDVJBCyO/hr5v7Qplb9IB/O5bDc+yDPEKVSR8Wu4KP5P1V7V68q2HJE6raaTo0Qi
         SyWxfcIbkfpUuHLqj9U8DoApu3nOhuHorg15n8k44kyTFyJiM0aLAAQcvoh4sCoasHK2
         1vPASH/Yh9QHW5OyZ2Xq4eoYN41B+LCF+RBAEE97V+QVxe7vgvlhPJUG3QhUkO+6R+rw
         dTShR6WjXDiR9zmPKcuvXv4eDBbCTr/vKb4+wKrv63HQBkOEt7UFtcVaCZWEABR+kZvi
         cM7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uqK3Vn8r64qPCAXm/fQpfIPim5hZUSx7BwwUzOXWqmw=;
        b=qoZkTZ66M4vQlPBKOkyl4yMclpCsi5II19448VfX7mbeHjNsyBuAM7iU1qGGDVgFWS
         8sBC++N4tdWwOWehCw/wWXPnk1X3xdiVKRM6uyQ61gxOM+Jxf9NOXyUShnsQHcW2KkVQ
         kfbueQ9CkcanEeuJTF/OVNNKWs4vtHfLj4jUnjs/m9miqAKwk3WLk/vmPpd0aBTLstm9
         erKeryefAtqEh4bFJ2mAGQ9olG4mqUkoHct5wxYbDQGZDdfdgiANUcvZu/E/8JSU2kg/
         /i56Md/rtP0g/xqI49+AGmgbC9LFHtAYmvA6zY282JTLXxpGJbjXfSUhWbHfsojHH1Id
         zkFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uqK3Vn8r64qPCAXm/fQpfIPim5hZUSx7BwwUzOXWqmw=;
        b=lc7370drnbqTC+/Aa9UgMGj/8PiyNRCVXrXlJk5aSWLxp4mSDzn6Q5htE7hIYt5ofu
         lz3xsNDIn2Gm29nFqohd+s8LHyR9Xf1gmFgnnbx6tiYbB13TC8afNCjnqSvLTJI4pQVH
         llzS096tbh4DHldoqz0PFhy5KWMPIUbSW4v1OrFJC1yXgq+Kh6iCB67GrJWLn70ROj6y
         EJrzOW6iIoZqIviVc2ZhbEssUndxnePX/sdayR655/QkqZ7pdxJn6BmXPjXUAFaCiYL/
         6vdY1Vy49pSBIX1fZeXcg72XiSU/z23HAoQTX0LfJWDNKuGnJu0u/Fy08vtU7WOTV2zv
         sJ4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uqK3Vn8r64qPCAXm/fQpfIPim5hZUSx7BwwUzOXWqmw=;
        b=NCZBFQQCnNz0dnPJp2CMnvojXOqXw9ehv9R7BktEb1gYmbhVdp6YScfUVKGII+jMwn
         NMyco4TR+wVtt5Jgt5d+a2SgcYQd/TTlp/bf9Wg6hDDEMsrgWFt068Am8LCYRXti+8XB
         H0GA4pGLTbsGDaVh1QeF7CVMzkm9pBZZf0KsGLGlBlbK97qeZXwHjcAzsgYEDwwAyb2k
         ujtIC4fARKqWZcher8qsNUAP3CUB1gY/WzY3nJ/D1ThFNXCynWGGwxYlWEceVRH4SO7b
         OwLrBmTQk1/zo+yQrR4DHxDRJhguDfozMm1kaPOHg8c7ShtIX2n46ryVpiCzwakaMBQb
         8O5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532yaimOI6YTtOoL9VtEzHEw/Imrbw5Lgp6M0q7QGdsjxzhtQANH
	cz48wJLYHld3ArQagLFbM88=
X-Google-Smtp-Source: ABdhPJycNsrGHs90OFq1107Ztay0wCer3tPuN1TBvWyl2pcuWKH5OX1STnmt3ErMLD+W8UJoQBegDA==
X-Received: by 2002:a17:90a:ca09:: with SMTP id x9mr9065432pjt.89.1600362264996;
        Thu, 17 Sep 2020 10:04:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f92:: with SMTP id z18ls1340593plo.11.gmail; Thu,
 17 Sep 2020 10:04:24 -0700 (PDT)
X-Received: by 2002:a17:902:d88e:b029:d0:89f4:6222 with SMTP id b14-20020a170902d88eb02900d089f46222mr29383788plz.10.1600362264238;
        Thu, 17 Sep 2020 10:04:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362264; cv=none;
        d=google.com; s=arc-20160816;
        b=DyxrlrD5cw9oROBC5mmUdhuXSI01OGnATBn3MXyWvxdqh3qI9mvNobVOjq13XwXXrD
         tljLOTs3DYU66/hymboH1foh5H7SF/YJE6IuM2z/BnGrFT4e9ogFkboROXWVcf6f0e7J
         2G3625gBxa6ySAJ1llem+0vFONlgre+iKXYiHp8bmiKIzNrdtSic4+mHNbr9QM2wVzL5
         s0XTgrL05nvEpYYLDvGx/3bvzC9xLQO/M8yz1HpVl/Zwn+4nNd2ZaQzkED9b/wvJJoxa
         dvlu3v6A5nSeyx1HnR9hskEyfXioQ57YjBZrnxPnrXVTdiyVxcMTFrAjp5j5qeGmEe9d
         JWTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/lWRwEdAxJXuAsO8CpYMpU7ownBldXUsBBBOZYpCucg=;
        b=kwHkvxzHLAXbGwkNeWE6oahUdIEngSxt0064qR1bm8gd7dTS9pW3GgncrBOxnxXyvo
         zAjafr6b+MNfJQD2m0EvpKC9nfsm6oYUNFzqh2djmLERogANqgkGWHLouWd0xm9U9Dfa
         IP4hRWiYOQqTNmCljp2biiLYMk/lDFuc2VB1FLeA3lvtDgVmThf01c46FLd/L47m187R
         BmxTMUgWc5JwwHL7rggIDzM7xXwj0sHn62qHJQKwfjC+OAhKE3ITMTfjARlTkmwy+FBZ
         DFkEpLVkGG5JX5RhsmlsIt8Dcicp1tEAF/plR3FEiH+UqdDM1pm2UTWUBuyC7f9kYibx
         xGjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z13si43802pgl.5.2020.09.17.10.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:04:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1E30D206A2;
	Thu, 17 Sep 2020 17:04:20 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:04:18 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 34/37] kasan, arm64: print report from tag fault
 handler
Message-ID: <20200917170418.GI10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <fb70dc86ccb3f0e062c25c81d948171d8534ee63.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fb70dc86ccb3f0e062c25c81d948171d8534ee63.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:16PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index cdc23662691c..ac79819317f2 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -14,6 +14,7 @@
>  #include <linux/mm.h>
>  #include <linux/hardirq.h>
>  #include <linux/init.h>
> +#include <linux/kasan.h>
>  #include <linux/kprobes.h>
>  #include <linux/uaccess.h>
>  #include <linux/page-flags.h>
> @@ -295,17 +296,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>  	do_exit(SIGKILL);
>  }
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
>  static void report_tag_fault(unsigned long addr, unsigned int esr,
>  			     struct pt_regs *regs)
>  {
> -	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> +	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>  
> -	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> -	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> -	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> -			mte_get_ptr_tag(addr),
> -			mte_get_mem_tag((void *)addr));
> +	/*
> +	 * SAS bits aren't set for all faults reported in EL1, so we can't
> +	 * find out access size.
> +	 */
> +	kasan_report(addr, 0, is_write, regs->pc);
>  }
> +#else
> +/* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> +static inline void report_tag_fault(unsigned long addr, unsigned int esr,
> +				    struct pt_regs *regs) { }
> +#endif

So is there a point in introducing this function in an earlier patch,
just to remove its content here?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170418.GI10662%40gaia.
