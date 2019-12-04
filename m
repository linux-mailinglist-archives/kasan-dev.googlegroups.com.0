Return-Path: <kasan-dev+bncBC5L5P75YUERBNFWUDXQKGQELB5VOTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 434F81136B2
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 21:46:45 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id y23sf364407edt.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 12:46:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575492405; cv=pass;
        d=google.com; s=arc-20160816;
        b=lqaon7CTVx10M7p9FYZySdFOhZ6GnNkZnhvZBk2kwnJYYPFwmt3idQdcNPcmOsdxr4
         lxqXa4cIqqaVxyYWcUfTwCmCltZNLk4e7TUhmQU7cFjtbU9zglLz25t5A+uk5D6UTXl5
         Ndw2ljCEmDDkaHt1Hd9NDMb6ukBuR01ywQnRzIeaRuAwRNHFPAUORodK0hEt2bBnYCFN
         nBximv7jVllJwmVvDkSVKiyozCgsoWKsdEOvyk02L58Dsd10yYWfQyc/vP9PYwxP62CD
         +3YjepGoK3a4pS5tZygCKnK+Y5nJHok9cl8GVNM8e6zLHaTylDrqzuYC74RHWC7h+F1c
         CFEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=uWAHg6TDBUFsxsYd23DpbZtDPkHzXQYGwy59EgsAt4k=;
        b=XlomqNJymmacj2NqaeFfQPNwFvxVBeaehVFNQjhCBWYaLdAFNv+bNfCHN2FQ4k9Mbe
         doQkfH9e7uZ9xqP7iKiRNvLy5b9oA7LsUgCCEQxqmUgcGyLAHshZANfszBam+8DMilFc
         OBF9n2rUtoruY1OgImiBUeXKllZZpKSMA9vmBNxArqRvcWdCnk9WndCuywkZzmhvp2bW
         fdcv+OCQ76KGaEdrFVH6mTO1hZPbAdC3DV1Qyi9SCC89+9lSQwUcn7UsJVFl7faQmjvu
         Gb+jZ/oylNUzhClYIPZRRA/8E7aJ6heLgRo3+YRgjEAmqpdpPNss/qhOVc1orUc/Z5Ju
         PkXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uWAHg6TDBUFsxsYd23DpbZtDPkHzXQYGwy59EgsAt4k=;
        b=sX6hhyFA7uMkSNiNnWhfv8zqm67P1uiaar+gbknwtZgzzwcZg8ea+FBSGQG6+uOK53
         OJr23dIt7HTk6h44aq/G8AViFM+4Fjy3itPEOyF+XupJBQERW6M78l5HZU9IhrMZe8oj
         v4Q+kAcggBc0Uq8PfAByodtUKDwNtxdUoXk6cgRUu69s07LEDdPi/27mxKuLqc7z1s2o
         AVO5eDiyjHYVXfkqoQfa2sjkNJF5eM6Fmnaz3bUxoPkmW1wMGwiva3oONTkroj+34Rwr
         aBMcGt+s5nt1AfmeDU7t/kLHFwOujpgzAWTeO/76qITEEqu/6MzTaO0CWe0SDy/DmN3f
         bizQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uWAHg6TDBUFsxsYd23DpbZtDPkHzXQYGwy59EgsAt4k=;
        b=ggDnaN+4BF3gW8kuSwXyXv0wC4o8JgIur0/s7M/OUX+ofTu9tiqpiRuk9PYRdE4ARh
         DFz74A/HvSvmJJZlbJCqIGWb6rKBv51XQ18c0qwDgn6kItGMfUxtUrL/DQsG1MI1Y62p
         S6OOULU9m9ZZZWvV1SJDGnGvHh1rti4eSvDoqEq3sNGqrUdm18o2Colah2PuYPKkK5kb
         MC0rusAW/MlV7juYIyVknEHq0NmpDIRPs34CEzLfH/Nb8A8HEdE6yYvh8HxoIiJc31HA
         qSsBb1ASPRCxbrR3O3/AjuoqpMNlOr0H/fewX4OOP6JE5jUmXK+vHpia+CVwaemFq+hy
         10ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdT/aqN/YAwqNH8qlN5FmrrHLxQH+lgRfyAhAzeBxUgFaHq3cz
	p7tXx1j7qXBKAjWkn103OR4=
X-Google-Smtp-Source: APXvYqw/q8G6Baqfg2FetIeJRNUova59H8dFzipUrc9IyrutE2VHFaR31OU+pLR9qLK/DLTeQL3HJQ==
X-Received: by 2002:a17:906:5e4d:: with SMTP id b13mr5345286eju.266.1575492404941;
        Wed, 04 Dec 2019 12:46:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:355a:: with SMTP id s26ls217379eja.15.gmail; Wed, 04
 Dec 2019 12:46:44 -0800 (PST)
X-Received: by 2002:a17:906:d924:: with SMTP id rn4mr5176814ejb.213.1575492404506;
        Wed, 04 Dec 2019 12:46:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575492404; cv=none;
        d=google.com; s=arc-20160816;
        b=TH6TRkAXfQvi45sRXeozLebXzSRCAbr3oUcmyfdNTUqENegQ2rMWt+51JFbWB5tF4h
         jFWDSqWEFSH9B44T0MZZBChAXuVZKQfdEd7xt4r/Q1IQ9uBZxm3UXk3mvqrerapzvK1K
         od8pzQX42d0U5O4T534Zk9xEBIcesM7ZFd7DCbgEyZjGHAiFiAkZRh57Jw0qW3j/YE5s
         JbKLSczzBNs2PKzhcMvyBzJxjz/IrGxxLO+ED8ckrrEzIEnKnI27tvgBc3RTX3mSyic6
         WGmrOJve6iHj8D9rRH3AbVA5CVCOjVbh+Fpst2vWv1f1YbN4qr3Y6dlgccsaU1X2/tKh
         MSkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=m1yQAMdr7eHILji8pyjCSNwzoCxPqgNsaaUUpdHlVf4=;
        b=BOCkChNtGa0/U3cJLekL2QR0aJv9iiA+C+lWJ6iIJLU9Ki/CWxjAtQrS29NFmzeDW8
         jBhxclGQZ9ZHfCjpc/7nW4cnu6NyskpKASlzPmJDte6DiogvMGXm3nQlgq9l05QC2fJu
         ehCxBpGHIu3M+/TVLXQu86j79/Dkp4wxqBiDlCjbhYs0qIdqEC8q+AxcIM1um6wr9r5a
         dkUGDH7l/zeynt2UAs2/rUHhVrmsD77Drtu6pclUoQYGigIqRV+kj1S30wL9l67Fp5Ov
         BzfaYOisFd0BngaSGwoy0N7XioALB6SzZ7kLJaTpnteKe1SdfJLlgssAOlxCaUuvnbMb
         bo7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id cw7si574904edb.0.2019.12.04.12.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Dec 2019 12:46:44 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.5]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1icbXh-0001mE-UP; Wed, 04 Dec 2019 23:46:38 +0300
Subject: Re: [PATCH] kasan: support vmalloc backing of vm_map_ram()
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com,
 linux-kernel@vger.kernel.org, dvyukov@google.com
Cc: Qian Cai <cai@lca.pw>
References: <20191129154519.30964-1-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <cac9cbcf-4286-ae34-d150-79ea81a366b0@virtuozzo.com>
Date: Wed, 4 Dec 2019 23:44:29 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191129154519.30964-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/29/19 6:45 PM, Daniel Axtens wrote:
> @@ -1826,7 +1842,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
>  
>  		addr = va->va_start;
>  		mem = (void *)addr;
> +
> +		if (kasan_populate_vmalloc_area(size, mem)) {
> +			vm_unmap_ram(mem, count);
> +			return NULL;
> +		}
>  	}
> +
> +	kasan_unpoison_shadow(mem, size);
> +

This probably gonna explode on CONFIG_KASAN=y && CONFIG_KASAN_VMALLOC=n

I've sent alternative patch which fixes vm_map_ram() and also makes the code a bit easier to follow in my opinion.

>  	if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
>  		vm_unmap_ram(mem, count);
>  		return NULL;
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cac9cbcf-4286-ae34-d150-79ea81a366b0%40virtuozzo.com.
