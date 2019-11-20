Return-Path: <kasan-dev+bncBAABBKPV2PXAKGQEEOISEKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 93711103612
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:34:50 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id g30sf16618614qvb.11
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 00:34:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574238889; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnP2fl5Yz0GCy+WwdTaqA1fTqKox0v6xITZ3tpSqtpXTVpJl6dheCCv6flj9dNDS/c
         eokfsvPAZ5aNfiRIiBvIrZ2UZz/2EzuFaSQN19b73E7nW9xVEiHmt3DYUW3Y+xfQE/aT
         l9eofRA4fHKKwrtThOe/1nX8MmbsTQdIsHT0WiUT0VAv6L+o2aDI8yoAwZfSTtISnTyG
         AVUWIIpy4OA7rFye2+Yr169WZzY55FQugKsfuaIXFEgD7tasHM2beQEvzvMjau6HwLj9
         8ppUIyK6a9AOxVCv91/GCgT5kpA7O4fITioDlu/9NIvqiPpGiBRPxBRO7q6w/BeJaXnZ
         qOtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=cpckw6bPlmyjP82Fy73wkHlUEQeuRxXd/TJsl4lSp/M=;
        b=V6qUiUPvnpZ8FiGIjOL17xlq0bbEnY5/5dG8gYc0oGbeny8sjsxwwopSswlL5j1Gne
         M7ECrbpZPhFCO8UtZkS+Sm99+O6noq6T714dlY9y9wCNqh0pFBRhlipIT1SDj7xWBdye
         ioiu925BkuDI2j8UAaLT8dtdtIgeonrZlW8qU9wx9W+gHgsTRtwozIav4eHw4DXJwhUK
         5fmHwJuGGTMPgLwc+SM4X5BHAvwgN9YwipOnuu12FWqs9Ga8UwMQHXi3eAQb30gt12lv
         UDeSL3kwGCpH+oWv9qAp0VcF2AfCGglupr/8jGqBRhoExgUPH6mORqKyl5bf3/what3q
         wmtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tIc0hGv8;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cpckw6bPlmyjP82Fy73wkHlUEQeuRxXd/TJsl4lSp/M=;
        b=cr8r4AQCIo1CwbuEpC2qwqDbTkT+TaWBBUtrsYCqX5ZVTxnTk09MA6KNI2S8HQyYcj
         QW2IlcGkTxA+n/ZtSXtS5qsTpdKhB5EFcJovOoWPRliNnJ5kYn7I1SPk5KhIIxoHNA7/
         /5s/B+zmTm8AJf4/3u+AUrH2X269X1exyD/YNMiKqnF+NfvUOzI3BjMkXBJCh8G0A3He
         wgEq5ZVfba+4BzWzSclOzVJu2+dJ6QCMuAz8eqh7mZPhUYiM+ivq/IFffIvF87aoQ+PG
         KSHcF8Sn1r24wk55lhAQ4ADM94Uoff7hea9rQMqutDBwvlB6EJFBqT9pRJwISzy8Tdw8
         xafQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cpckw6bPlmyjP82Fy73wkHlUEQeuRxXd/TJsl4lSp/M=;
        b=HrMhYp4o2XmNkfY5xB/XtRUciKsyTZ3JHJY72JuMh5RJSCLp7Ed2YFdQ/+1eijfF7k
         shAANvJ0HbJDWwcKDnl43yw8hXJKs3MvFLvHrqbJPlvwnbOjJEK52ZTbi6TBpaai15dO
         ks0NWdF6mPe2Ua1aNlMxdwX2Jc3E5H1w/31j1QlPe2phKf0TY/axEalf7nSsprmIAWYD
         5y+Z8kr9q0i/gBiJ5kn74LOMbtA8mH0znnSafg4bLoyQvJdaHGTdw+jCwrS2uZUEtTsH
         He93rZskx9R/UYukt9D4w4EUi5blFYu8EoMTjFKuD3/veqjXH/4satzNxn2kfdWB+A4a
         YXHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSeAWL5+d5M8w50dh20xWFmlCTEShp7Frgw+84aQyMINNd8vNU
	GGCRdLIFebOAmSjO5im/ZvE=
X-Google-Smtp-Source: APXvYqy3hDiVC6eVgAiV47WjZDmDoPEwA8MG8c+BBK37dCGBkwTqJL3u/HpDdYS4pn1iTrqrme/keg==
X-Received: by 2002:ac8:379d:: with SMTP id d29mr1429433qtc.327.1574238889289;
        Wed, 20 Nov 2019 00:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:85c1:: with SMTP id h184ls477383qkd.3.gmail; Wed, 20 Nov
 2019 00:34:49 -0800 (PST)
X-Received: by 2002:a05:620a:914:: with SMTP id v20mr1284220qkv.473.1574238888959;
        Wed, 20 Nov 2019 00:34:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574238888; cv=none;
        d=google.com; s=arc-20160816;
        b=Mt5fL8NxTQLJkP1tBZcPkVR/TSzTdaZDQ4DKoIwoOQ/ipyKE6wZ1O8qySo3rdOg4QN
         RBEo4gt3LS4KRkiYd8DG5HRi125YdsPA79jLWfgqIqtH4Teq66X+JvrCxj1mtT9Q7lsj
         DnoaAHXv+iQWnMrdecspMQqIzJjvrVDisOrCJ57azTlGaEjD8uvDXAAt6InQ56Y/1bB5
         Hp7TFLvCueJx2vpPNpJCwISiq9hv2YVR7+hUavmCigZgmsbXoqS3ZysfgrP4nKxvSe/U
         usBwNUI8xH7nEBKCToJ78oOWGg7KBUfdTIVQQ1ZmfXzIe5fxAUK6KCQS5jKIkqGhJMx8
         pOyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=M2UT7PsbBttLm3d7KtnkpApkgoUAHdiQRcC9lfgSQY4=;
        b=VKDNKnvzFwQ7vKSn6LXUaUPHQNS50Ui0UnyWVsY4NnCyWFoxfkUrlFTZhMF4JuqtJx
         pJZyv+SgSD/YMQ1F5cYBYMW12TyHN+1h6Qevyi7RJ5t8tMjO5GwHef88B/Tf74s81n0D
         /JN99zHFOd4wZgfNngwLMUypMUQJ8W74SXiVubPFlUeyJvViIa1104Y11DVu26WXGSI1
         hIuo7cVpyLYWlO1fv6WGYbZ1cgAcVoPasJfAELUw0HFGbrWjwiA9GbYbOFHQY8c0IQQW
         kqJpi+rQ0b9ep77cNn22zeDucL2iHeBMazzwlueysY6b8pmpEHZCZzsaChSkDofuvHmm
         gOqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tIc0hGv8;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id z90si1108079qtc.3.2019.11.20.00.34.47
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Nov 2019 00:34:48 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 011dff86c9a24e339ba061cd43622e34-20191120
X-UUID: 011dff86c9a24e339ba061cd43622e34-20191120
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1433983432; Wed, 20 Nov 2019 16:34:43 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 20 Nov 2019 16:34:37 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 20 Nov 2019 16:34:48 +0800
Message-ID: <1574238882.20045.2.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Wed, 20 Nov 2019 16:34:42 +0800
In-Reply-To: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=tIc0hGv8;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2019-11-12 at 14:53 +0800, Walter Wu wrote:
> KASAN missed detecting size is a negative number in memset(), memcpy(),
> and memmove(), it will cause out-of-bounds bug. So needs to be detected
> by KASAN.
> 
> If size is a negative number, then it has a reason to be defined as
> out-of-bounds bug type.
> Casting negative numbers to size_t would indeed turn up as
> a large size_t and its value will be larger than ULONG_MAX/2,
> so that this can qualify as out-of-bounds.
> 
> KASAN report is shown below:
> 
>  BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
>  Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72
> 
>  CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
>  Hardware name: linux,dummy-virt (DT)
>  Call trace:
>   dump_backtrace+0x0/0x288
>   show_stack+0x14/0x20
>   dump_stack+0x10c/0x164
>   print_address_description.isra.9+0x68/0x378
>   __kasan_report+0x164/0x1a0
>   kasan_report+0xc/0x18
>   check_memory_region+0x174/0x1d0
>   memmove+0x34/0x88
>   kmalloc_memmove_invalid_size+0x70/0xa0
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Reported-by: kernel test robot <lkp@intel.com>
> ---
>  include/linux/kasan.h     |  2 +-
>  mm/kasan/common.c         | 25 ++++++++++++++++++-------
>  mm/kasan/generic.c        |  9 +++++----
>  mm/kasan/generic_report.c | 11 +++++++++++
>  mm/kasan/kasan.h          |  2 +-
>  mm/kasan/report.c         |  5 +----
>  mm/kasan/tags.c           |  9 +++++----
>  mm/kasan/tags_report.c    | 11 +++++++++++
>  8 files changed, 53 insertions(+), 21 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index cc8a03cc9674..2ef6b8fc63ef 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -180,7 +180,7 @@ void kasan_init_tags(void);
>  
>  void *kasan_reset_tag(const void *addr);
>  
> -void kasan_report(unsigned long addr, size_t size,
> +bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  
>  #else /* CONFIG_KASAN_SW_TAGS */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..4bfce0af881f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memset(addr, c, len);
>  }
> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memmove(dest, src, len);
>  }
> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memcpy(dest, src, len);
>  }
> @@ -627,12 +630,20 @@ void kasan_free_shadow(const struct vm_struct *vm)
>  }
>  
>  extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
> +extern bool report_enabled(void);
>  
> -void kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
> +bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
>  {
> -	unsigned long flags = user_access_save();
> +	unsigned long flags;
> +
> +	if (likely(!report_enabled()))
> +		return false;
> +
> +	flags = user_access_save();
>  	__kasan_report(addr, size, is_write, ip);
>  	user_access_restore(flags);
> +
> +	return true;
>  }
>  
>  #ifdef CONFIG_MEMORY_HOTPLUG
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..56ff8885fe2e 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -173,17 +173,18 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
>  	if (unlikely(size == 0))
>  		return true;
>  
> +	if (unlikely(addr + size < addr))
> +		return !kasan_report(addr, size, write, ret_ip);
> +
>  	if (unlikely((void *)addr <
>  		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> -		kasan_report(addr, size, write, ret_ip);
> -		return false;
> +		return !kasan_report(addr, size, write, ret_ip);
>  	}
>  
>  	if (likely(!memory_is_poisoned(addr, size)))
>  		return true;
>  
> -	kasan_report(addr, size, write, ret_ip);
> -	return false;
> +	return !kasan_report(addr, size, write, ret_ip);
>  }
>  
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..c82bc3f52c9a 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -107,6 +107,17 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>  
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +	/*
> +	 * If access_size is a negative number, then it has reason to be
> +	 * defined as out-of-bounds bug type.
> +	 *
> +	 * Casting negative numbers to size_t would indeed turn up as
> +	 * a large size_t and its value will be larger than ULONG_MAX/2,
> +	 * so that this can qualify as out-of-bounds.
> +	 */
> +	if (info->access_addr + info->access_size < info->access_addr)
> +		return "out-of-bounds";
> +
>  	if (addr_has_shadow(info->access_addr))
>  		return get_shadow_bug_type(info);
>  	return get_wild_bug_type(info);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 35cff6bbb716..afada2ce14bf 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -152,7 +152,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  
> -void kasan_report(unsigned long addr, size_t size,
> +bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip);
>  
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 621782100eaa..c94f8e9c78d4 100644
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
> @@ -478,9 +478,6 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>  	void *untagged_addr;
>  	unsigned long flags;
>  
> -	if (likely(!report_enabled()))
> -		return;
> -
>  	disable_trace_on_warning();
>  
>  	tagged_addr = (void *)addr;
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0e987c9ca052..25b7734e7013 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -86,6 +86,9 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	if (unlikely(size == 0))
>  		return true;
>  
> +	if (unlikely(addr + size < addr))
> +		return !kasan_report(addr, size, write, ret_ip);
> +
>  	tag = get_tag((const void *)addr);
>  
>  	/*
> @@ -111,15 +114,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	untagged_addr = reset_tag((const void *)addr);
>  	if (unlikely(untagged_addr <
>  			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> -		kasan_report(addr, size, write, ret_ip);
> -		return false;
> +		return !kasan_report(addr, size, write, ret_ip);
>  	}
>  	shadow_first = kasan_mem_to_shadow(untagged_addr);
>  	shadow_last = kasan_mem_to_shadow(untagged_addr + size - 1);
>  	for (shadow = shadow_first; shadow <= shadow_last; shadow++) {
>  		if (*shadow != tag) {
> -			kasan_report(addr, size, write, ret_ip);
> -			return false;
> +			return !kasan_report(addr, size, write, ret_ip);
>  		}
>  	}
>  
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 969ae08f59d7..1d412760551a 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,17 @@
>  
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +	/*
> +	 * If access_size is a negative number, then it has reason to be
> +	 * defined as out-of-bounds bug type.
> +	 *
> +	 * Casting negative numbers to size_t would indeed turn up as
> +	 * a large size_t and its value will be larger than ULONG_MAX/2,
> +	 * so that this can qualify as out-of-bounds.
> +	 */
> +	if (info->access_addr + info->access_size < info->access_addr)
> +		return "out-of-bounds";
> +
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	struct kasan_alloc_meta *alloc_meta;
>  	struct kmem_cache *cache;

Hi Andrey,

Would you have any concerns?
Thanks.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574238882.20045.2.camel%40mtksdccf07.
