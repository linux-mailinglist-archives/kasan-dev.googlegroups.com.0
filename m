Return-Path: <kasan-dev+bncBC5L5P75YUERBFG2S7XAKGQEK7LTKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 90EC9F5AEB
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2019 23:32:52 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id x17sf1568965ljd.15
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2019 14:32:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573252372; cv=pass;
        d=google.com; s=arc-20160816;
        b=ARMFAxTUPINeaK7kG8MHXy6PK8ZjtypplxL8Qly8IrYOnkdJBguaZes0J6st6KwQT0
         RAk+2Fl8WBfbRY/Ww1797tXW0HjX1c1/Tdj38wGokKecwEgXu98vDjgaSeGnwacA+RhZ
         +qZA+9u9cPGUXL3dHQPvHTmbhNdhfuLnaNX/yDSkwmay3GNjSAZMO5hoQUg9QvP1QYJG
         sTgP7CzBbtsS1EZeSDhMJ4+ghsDFCg64guIVoCSGVyPKz+m7KSVb1hdfngB0Zcq5uIB5
         6kOeRawek4iS8J1LvcAexkrrCunUeraadTWS5/2wrRV2TE+XTcoEzqsuIF/iXhH0YEYt
         +M1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=0CgDi1FNNmmCAgWNWXg/tKkAtP4IF3ljZHwKAtpv6BQ=;
        b=JzvKZRF1nRsDMJ04yuqEARKAlFVyLcNLxLQgPwPnY3NSI7la/zIhI9ZA525YE+lZAW
         /X3yarXgvTPWkkJq/jzeLtE98nespEtz7ylocE2Kh3d5dqiUnQ+o0Acq7M9Ivqjnu2bE
         l3nMzjsKZjnewFBmOdGjusB8BD9GWiB2Rw/v3Wb+VoYIIl2IZBle4AkK6vPWcyw7wiTv
         ym46BoY0NZDXdHUPNbD5fBI8SVKXexthGDmAhFrhj4UU2aoyFaNht0MVj3duUrm/zZpv
         mEUEglPE64kPm+UX7tHA3LeMlMolY5yIUvn052zWle8LBSe9PjyAGTaRxTtCyOPgLMr3
         zEBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0CgDi1FNNmmCAgWNWXg/tKkAtP4IF3ljZHwKAtpv6BQ=;
        b=n7rP1c3l2Qgg5EfBUrZPjU+8lBTYdqDKWneGgfN8YmG66I9Vtd/nE0tuP6swqOtxEc
         VcLay73KfobxEbcxxTlmgQKabZIVgmeICVNsHmkxcNHG7R2npUDLMBTwX7bSAWqJndJN
         relh24yc0F82SZ0zk1qXLqUnZzcYUq8dNbyHRQZ/aWyLj/YCrnrQO+WsAeYygjos5vtC
         OeABiJ8HTvFrJOdqCH4RpIKc/Wf+I/rhN0qko0mDRc8Krv9XfYXjV9SyLq+aZcO8vRmK
         o31iB/376Rva6T7m+2C4vM56e91nOf25Y7mCx2mIwfXFrrE43WNwIW/GeGNXdhIpC+i+
         L2mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0CgDi1FNNmmCAgWNWXg/tKkAtP4IF3ljZHwKAtpv6BQ=;
        b=rNK8BRLyuaMwZnmQ5GUP1oc7peTv9bVVlSg1VxSllsPGgNVRH472Pm4KOZykLOYfFw
         RLDTsGDgeAb28YiwrBjoLY9cvhY5KYrm2CiX1XnD6smSf7rKPQy6i3ttWZOjlpeWioGT
         mu0kFxoxru/fV3KEqksKhJcd4MmfojQ6zrRSYyvgefuBe4GAesrbjDXsA8hYt6nEQQIF
         d02l4iiqrqSUMd68uYZekERKUIc0mFq1H70JmdWcbfahMiXwOznm44Bf8/IQmgAFVdLl
         FRKq//WnzUOGf6NV9ueWA+LxyddgSzoA018wmGVw8OFlZOLCQlq3GnRbcVb+DrXRYKPW
         2ifg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXr5GInuhJgPBN65/cSxSDv3cmJksGaQvRsgBngEJQyhu5pqjWq
	tLD817JhgPnJWbgXFwaNcF0=
X-Google-Smtp-Source: APXvYqypP+Yuteuu9MKqrHaUP72bbLC0pBhIQMX0ek2OZVCk9nVL9boW6e0UgbWWZak/4Dh8shebLA==
X-Received: by 2002:a19:6108:: with SMTP id v8mr7966506lfb.160.1573252372129;
        Fri, 08 Nov 2019 14:32:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:904c:: with SMTP id n12ls143917ljg.8.gmail; Fri, 08 Nov
 2019 14:32:51 -0800 (PST)
X-Received: by 2002:a2e:9784:: with SMTP id y4mr8433426lji.77.1573252371578;
        Fri, 08 Nov 2019 14:32:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573252371; cv=none;
        d=google.com; s=arc-20160816;
        b=rb/qWfYMyiUHzz2r+Q2Xx/aQUEcsrw3JXGttXESC9BBzCerWZTqStXI5PUQBNMLxoU
         kSI5AlecKc0YMyoyFkb+3wFUCSxEMB+N2lMYNOmke2rKmH0+fgMNllPZboK/zU0/bYLG
         UcpLGcVEyvEQiULPep1baX51qa3Hdm4dM07IYwiATjsFMgGWRDfOt5WG4cx7sx+0b0Dl
         BgGzjiq/gky+CuXUAgNRP1Nnf/lhlJUvbgUo1PwIYjf4t8HfOqLNA6m91BYyyPzK0jEc
         uwUJz88Bb1XjSNlq+7Idu5zoNPJhOiIj/DKQWEzB2LBew+rVfBdvRKkWr3E4jQ339zuE
         tINg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=DAGbZhEkDRZK9EiB+szjFQxk/c8yQuPafI2xz7iM9Mg=;
        b=cQYOVbsjgC0r3pbSeBJ53kgitE9cc7JFh0hbmeJsv3YRD+kJpW444V81/FbKvJmyn5
         eCT70CNXuCP6vZvjWCRbcgx38OZNJappbxxeZJGAHrwAQdyptfZ1A5cHlMbAly0HgUVg
         e50/3JKbm46KRKfqlrfn1z1q/ZmIGX9jhBmMxIfx+5iK35tPxqvtWAfyYLl/A8m9Jfnu
         xDwkFrOP2uEeFy0rmFw9hkFFK6ypaBTseHD9ZSPrZBeuGoePYg8mwngSTykvYNe4mcqT
         rzfhrsHxzD9DsTnijR+K2s9nVGBgOrrVk56tul9v2my2sswqiSi6tVoD69L8bmeKqXlM
         bipA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id j14si527628lfm.2.2019.11.08.14.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Nov 2019 14:32:51 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.61]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iTCnz-0006wD-JO; Sat, 09 Nov 2019 01:32:35 +0300
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
Date: Sat, 9 Nov 2019 01:31:12 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
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



On 11/4/19 5:05 AM, Walter Wu wrote:

> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..4ff67e2fd2db 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
>  }
>  EXPORT_SYMBOL(__kasan_check_write);
>  
> +extern bool report_enabled(void);
> +
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +	if (report_enabled() &&
> +	    !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memset(addr, c, len);
>  }
> @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (report_enabled() &&
> +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> +		return NULL;
>  
>  	return __memmove(dest, src, len);
>  }
> @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (report_enabled() &&

            report_enabled() checks seems to be useless.

> +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> +		return NULL;
>  
>  	return __memcpy(dest, src, len);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..02148a317d27 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
>  	if (unlikely(size == 0))
>  		return true;
>  
> +	if (unlikely((long)size < 0)) {

        if (unlikely(addr + size < addr)) {

> +		kasan_report(addr, size, write, ret_ip);
> +		return false;
> +	}
> +
>  	if (unlikely((void *)addr <
>  		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>  		kasan_report(addr, size, write, ret_ip);
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..52a92c7db697 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>  
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +	/*
> +	 * If access_size is negative numbers, then it has three reasons
> +	 * to be defined as heap-out-of-bounds bug type.
> +	 * 1) Casting negative numbers to size_t would indeed turn up as
> +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
> +	 *    so that this can qualify as out-of-bounds.
> +	 * 2) If KASAN has new bug type and user-space passes negative size,
> +	 *    then there are duplicate reports. So don't produce new bug type
> +	 *    in order to prevent duplicate reports by some systems
> +	 *    (e.g. syzbot) to report the same bug twice.
> +	 * 3) When size is negative numbers, it may be passed from user-space.
> +	 *    So we always print heap-out-of-bounds in order to prevent that
> +	 *    kernel-space and user-space have the same bug but have duplicate
> +	 *    reports.
> +	 */
 
Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
type, but at the same time you code actually does that.
3) says something about user-space which have nothing to do with kasan.

> +	if ((long)info->access_size < 0)

        if (info->access_addr + info->access_size < info->access_addr)

> +		return "heap-out-of-bounds";
> +
>  	if (addr_has_shadow(info->access_addr))
>  		return get_shadow_bug_type(info);
>  	return get_wild_bug_type(info);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 621782100eaa..c79e28814e8f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -446,7 +446,7 @@ static void print_shadow_for_address(const void *addr)
>  	}
>  }
>  
> -static bool report_enabled(void)
> +bool report_enabled(void)
>  {
>  	if (current->kasan_depth)
>  		return false;
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0e987c9ca052..b829535a3ad7 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	if (unlikely(size == 0))
>  		return true;
>  
> +	if (unlikely((long)size < 0)) {

        if (unlikely(addr + size < addr)) {

> +		kasan_report(addr, size, write, ret_ip);
> +		return false;
> +	}
> +
>  	tag = get_tag((const void *)addr);
>  
>  	/*
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 969ae08f59d7..f7ae474aef3a 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,24 @@
>  
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +	/*
> +	 * If access_size is negative numbers, then it has three reasons
> +	 * to be defined as heap-out-of-bounds bug type.
> +	 * 1) Casting negative numbers to size_t would indeed turn up as
> +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
> +	 *    so that this can qualify as out-of-bounds.
> +	 * 2) If KASAN has new bug type and user-space passes negative size,
> +	 *    then there are duplicate reports. So don't produce new bug type
> +	 *    in order to prevent duplicate reports by some systems
> +	 *    (e.g. syzbot) to report the same bug twice.
> +	 * 3) When size is negative numbers, it may be passed from user-space.
> +	 *    So we always print heap-out-of-bounds in order to prevent that
> +	 *    kernel-space and user-space have the same bug but have duplicate
> +	 *    reports.
> +	 */
> +	if ((long)info->access_size < 0)

        if (info->access_addr + info->access_size < info->access_addr)

> +		return "heap-out-of-bounds";
> +
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	struct kasan_alloc_meta *alloc_meta;
>  	struct kmem_cache *cache;
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34bf9c08-d2f2-a6c6-1dbe-29b1456d8284%40virtuozzo.com.
