Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5KUOGQMGQEQXHBCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21C00466501
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 15:17:12 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id d13-20020a056402516d00b003e7e67a8f93sf23739736ede.0
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 06:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638454632; cv=pass;
        d=google.com; s=arc-20160816;
        b=vBDpv58YU1g5XYSs6nd3nd0BGcFBUxs1wsgA0jtSFOuOEK/CU45HDcJYAeWq53yPrB
         l4oAJ9tk9LHfC3UDOmEul5gP8uE6uPL84OJ5tgRepbPnom6kxWEPLQDUmOexhYijsgv1
         4KjlMj2baKhIvFHIEXfySF+ODgXU/r85HefSiG1AOh13xToyXnd9oP8Y6JHmXCpHRzg7
         8dwe1tenbFNnZxT8dgG1OMKEZvqDQ+Sb4QSz9AV4MuIma69IRDDa8pZ0VQEJeUSoLFJF
         KOGODC/7woMTYt/k0d2J5UHLh20gJcCrgt022Ev5SiPLszw2qUpUHru4OXMe+iTARvh8
         Nc7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UJWsfHSrx0pMXy27Rskw/2POD9YcJSnouLrsGG6z8sw=;
        b=JBLEDMCdAff71tCvUgwG4NvTsKatY1JB26zrFRHDlWE4xb6rvbKiaAYBWPuggiD0me
         W0oSwZ3hQuxZQBxSkleqNEzPICXPNdF60RNk7X1S0k5TZ1xNpujXdj5jY0I7YVjDzIvx
         yrKwwahTdWMJsvQFL93237OW63DhUtJuoTk4u48VxsIUfrFsh8hkmQ+M5LkMo/z2d/T6
         L/N55s+x81uNmhfM2sKYglrO90P9L1r8UfHSFFl+Jz/5TLFAPjjjuRCnCRlQ25SDMhII
         4bD6vYeaHBpFVpLxcfRD5quDd5HgzDyye4nKAXDuWZWH3RW4pWXpanBItGTnVvHT4lm0
         xHNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MJa0kwqO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UJWsfHSrx0pMXy27Rskw/2POD9YcJSnouLrsGG6z8sw=;
        b=sklFy450AQpjMDy4LFuz582ifKZgFNobz7ZgeItgOqGpwTqgsU0xyny29UL6V5IAtI
         E8JLp0RmXK7vf6sUs6+IcRZ3S2S23xL/Fup2XL2CkUO3IT2Dp7wdTWLMUtmW3qTv0Uep
         ++FRz2DfPEWjrM68/cUtvzeleIDl2DoaHB6JFdlXcKGeTtTHSkt6P8brySbFHqO+wTKU
         i/pSwEE49ctmSN9hNdmnm5IsskCl+XhWrzfCNuPlwnrjghHCy/a8ysKCjZ/GP4v7FkWD
         n3BnWUG8n130h5Hs4uWmmAEKIczTWDGcnYZSVY3RQIQQyjKKWLRGsazbn6MQnMffJm1b
         BdCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UJWsfHSrx0pMXy27Rskw/2POD9YcJSnouLrsGG6z8sw=;
        b=Wuke6QF+dyFN+Ggf9WHWO2m9ogQ02+G/HdIzCTjBEAH91EnJzJtrFKgmW6DiiLCiSN
         4Yrg2kcRY0NGY+k9rrcSUw3ZjBulFId7nNXPs/WtbSvKWeIRBEXQ+LnEKTLTBQUFnV17
         9GcuH7DPVu4NqxcfPSglC3LNixalX18cv59f/zYRgnWVklPT5Z1iHlCZCzxo/UgEfxd9
         icLtWoWQLkVOgbGF8xjtv/hzwDtPk34kWXV3oiGgV67Pfsiemssi2zmtAs5UBG6e7Yn8
         d7aRq6e9RboEDoPqB/EN5RUNffSAsx8LiGrdtrZDg8xL+TBweuQwTAsVpEKKn9mzihD2
         mEDA==
X-Gm-Message-State: AOAM531dIIFqhkCYn210R4pjzhdc4/VdILXtmt4FLVibPr2Eg9iz2AVC
	qPsXfbwO9L3pwtDl52gOE4E=
X-Google-Smtp-Source: ABdhPJxwe6wSCsP2IBIEw1VZo6uTIwOpzxpiD5tCoPxnzz9Ig+Xs/imR9H1UrueUWLzsq3evkWGNyw==
X-Received: by 2002:a05:6402:2751:: with SMTP id z17mr18261431edd.296.1638454631904;
        Thu, 02 Dec 2021 06:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c98f:: with SMTP id c15ls6485850edt.0.gmail; Thu, 02 Dec
 2021 06:17:11 -0800 (PST)
X-Received: by 2002:a05:6402:35c2:: with SMTP id z2mr18589469edc.92.1638454630893;
        Thu, 02 Dec 2021 06:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638454630; cv=none;
        d=google.com; s=arc-20160816;
        b=kYA2zh8j6HmGLtgYM3zD+xtkgANsJ8UoxlbVVzEU2NWn+U34pxZUwfaksGaY6SlU6e
         SdUL57IU7d5Eh7DT4Dw4Xu0WSukgGTmMFnWgFVM4aNCk5XABTxBryJVmhNEKjpnFNfcL
         fVNZmzHxIFn682DGiEy5242lBJ9x6k8dwxptcD7wB/qXG3HF/VYGs/R9q4wdtY0bngI8
         r7i7hKJXeZygFy3lLzB1ratAKBojC8799P3ODwyFFaRO7L8YdI1qiymazxEEdXF6Sucl
         CCzDGk2+qKe9LDxvWoxp9VK1e7QkNWgL8DxlhJFGGgzToo2+Tw6/8LUbakWY39O4O7BS
         cY+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6crFa5jut9iv6wEdQoYG1FoOh3TuBW6gGjCQbNAlfgU=;
        b=ELG3dKee8UfZpRVNGVrY+9JWpqWQ+guDUwHv3oolytSkSXmIDFkWHDCQ8jaEHR/Vqd
         WBY8jWWNkL3sL6ozpSl2j2vMMY+bcUxPbBXdLmfnOX/nlGw7LdnHF/bZ47LD9PKm/p5G
         3+95gSAqmmrSnEtitawhiDSPWzYTxip+LsA1fT6mB5iHnxrPrKAUefc63VlJrfiZz+p4
         SW94L8Xr1d18t+cywCG5vhwxT2oLz85L9Ah4nIZUslF8+fAVW/Lrw7eGcJCq+ds+dI+n
         q2owEDugW6XhNeWdn5KT2QJ9qqxpVsc/5gdJHltoPw3Byi7OcWltbVRI+OtLu1tz1cZq
         Yzdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MJa0kwqO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id s8si164655edx.4.2021.12.02.06.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 06:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id v11so59990744wrw.10
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 06:17:10 -0800 (PST)
X-Received: by 2002:adf:f489:: with SMTP id l9mr15258640wro.268.1638454630376;
        Thu, 02 Dec 2021 06:17:10 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ddd6:f3c9:b2f0:82f3])
        by smtp.gmail.com with ESMTPSA id t11sm2717493wrz.97.2021.12.02.06.17.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 06:17:09 -0800 (PST)
Date: Thu, 2 Dec 2021 15:17:04 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 20/31] kasan, vmalloc: reset tags in vmalloc functions
Message-ID: <YajVYNBDOyI3hTx1@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <f405e36b20bd5d79dffef3f70b523885dcc6b163.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f405e36b20bd5d79dffef3f70b523885dcc6b163.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MJa0kwqO;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> In preparation for adding vmalloc support to SW/HW_TAGS KASAN,
> reset pointer tags in functions that use pointer values in
> range checks.
> 
> vread() is a special case here. Resetting the pointer tag in its
> prologue could technically lead to missing bad accesses to virtual
> mappings in its implementation. However, vread() doesn't access the
> virtual mappings cirectly. Instead, it recovers the physical address

s/cirectly/directly/

But this paragraph is a little confusing, because first you point out
that vread() might miss bad accesses, but then say that it does checked
accesses. I think to avoid confusing the reader, maybe just say that
vread() is checked, but hypothetically, should its implementation change
to directly access addr, invalid accesses might be missed.

Did I get this right? Or am I still confused?

> via page_address(vmalloc_to_page()) and acceses that. And as
> page_address() recovers the pointer tag, the accesses are checked.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/vmalloc.c | 12 +++++++++---
>  1 file changed, 9 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index c5235e3e5857..a059b3100c0a 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -72,7 +72,7 @@ static const bool vmap_allow_huge = false;
>  
>  bool is_vmalloc_addr(const void *x)
>  {
> -	unsigned long addr = (unsigned long)x;
> +	unsigned long addr = (unsigned long)kasan_reset_tag(x);
>  
>  	return addr >= VMALLOC_START && addr < VMALLOC_END;
>  }
> @@ -630,7 +630,7 @@ int is_vmalloc_or_module_addr(const void *x)
>  	 * just put it in the vmalloc space.
>  	 */
>  #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
> -	unsigned long addr = (unsigned long)x;
> +	unsigned long addr = (unsigned long)kasan_reset_tag(x);
>  	if (addr >= MODULES_VADDR && addr < MODULES_END)
>  		return 1;
>  #endif
> @@ -804,6 +804,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
>  	struct vmap_area *va = NULL;
>  	struct rb_node *n = vmap_area_root.rb_node;
>  
> +	addr = (unsigned long)kasan_reset_tag((void *)addr);
> +
>  	while (n) {
>  		struct vmap_area *tmp;
>  
> @@ -825,6 +827,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
>  {
>  	struct rb_node *n = vmap_area_root.rb_node;
>  
> +	addr = (unsigned long)kasan_reset_tag((void *)addr);
> +
>  	while (n) {
>  		struct vmap_area *va;
>  
> @@ -2143,7 +2147,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
>  void vm_unmap_ram(const void *mem, unsigned int count)
>  {
>  	unsigned long size = (unsigned long)count << PAGE_SHIFT;
> -	unsigned long addr = (unsigned long)mem;
> +	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
>  	struct vmap_area *va;
>  
>  	might_sleep();
> @@ -3361,6 +3365,8 @@ long vread(char *buf, char *addr, unsigned long count)
>  	unsigned long buflen = count;
>  	unsigned long n;
>  
> +	addr = kasan_reset_tag(addr);
> +
>  	/* Don't allow overflow */
>  	if ((unsigned long) addr + count < count)
>  		count = -(unsigned long) addr;
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YajVYNBDOyI3hTx1%40elver.google.com.
