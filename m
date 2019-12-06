Return-Path: <kasan-dev+bncBDK7LR5URMGRBLVBVLXQKGQE55VXT6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E61611568C
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 18:32:31 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id g16sf2114521ljj.12
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 09:32:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575653550; cv=pass;
        d=google.com; s=arc-20160816;
        b=R49mehQgp67JU9Vn5BSJews9e2+H3L5Vt9mdu3tbZ33GgxMcVrbN4dONWoNHWef6cY
         gh811BxNwFARoeN8zjhx0yCVs/4zmOEhPI4DJiCodXT9gxHF1TkOPzLWvnmX7gDFORht
         sMulxn/cv+oohzNao7V9W1cil23Kla88ae4OiST6LLY4Dpo95tiMOr91Om+pAcNyemdP
         rJGclEGLLzv3gN9fN5w/WCBOZJBJIBArXn3DNvF0NOMEkbLiN7neG191fCZ9Ug+BwzCQ
         vM9ilHFDhSL4g7mLYhZdaYNSRHw/VBnRLuSOlYcFMUTIRU/eCm4XJQyJsqQ+0yQUbPTj
         3FyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=Qr0RgZ+a/zM+SxkgK8YQOOF3fimOwozA4DwLbZMc1d4=;
        b=kbjo8Ywd/nfD5cpeT+mbaDypJydOXJ/fbDw73QrprictIGQIaMo8e9YIBVrZP+2jzu
         9EfQyaJciZ8JaYRU7MSm5ONBnfxcpnBezdUHpy3S+jyJzLEwTyrfaSo5M+E/WIAJ0lmH
         kV+ozXg53Mi+zib5ZWKefB5ycISEgqjowwE/5oox9XEAcPFdihNXYzHpHQ5JGPe2CXC8
         B/jWqkvDD/BrJYh0VnOazoR5RGgvHX6Yh0rWGWGdGgE8aBUojT9rzEbC6+zXNj9nk9KB
         ol5gt/EOQuc05MORZHwGyEEQcOuWdKZVKNC8oDti8GTYu3Tfdn5eeR2o1sEcxfTOLPeA
         YXOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rzTAITx7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qr0RgZ+a/zM+SxkgK8YQOOF3fimOwozA4DwLbZMc1d4=;
        b=rKDttWhb6actsgZZY246pwTEwQWF0XGk2cit9sRL/+BGEkYbh3gZJWFyYVTMdM5l1X
         JpPLHABW0KJ3i+eYmCCqiSaNAVU9JTTjf4rdHdRPB1XtUSqlu5mg4NMIZnYS/Fxp4e/1
         13r11N++trfeMD3sbnpmBBLaUydptG16I9uRk64CJNR9RHl0OVrugG9SLyFSn/kA+1rG
         LhuYpIUb/X4apM7m2xHl/LaWIiduS+R0XBD0M7wSprH6atMzhFfig5oxzny6Jxiwp0sQ
         TVXB+PcYtCOzQE6BF1OJ/bq1z2klcTbRO7nrayKQc8a/T7rzdz/CSClXOF5mIbzxrhXt
         DOeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qr0RgZ+a/zM+SxkgK8YQOOF3fimOwozA4DwLbZMc1d4=;
        b=ebcDbZ5yH+fM3JoVpsj8kUb23haMQsb56V6vCpfxmr+1wiVvAV3a4acqDwj/mR46nP
         kaNe5K4kTJwdIl7aXCgwzlls6bmTu6tsfmA8dEX6fkR39DHwtUJE34PF/sEqnHGL9RRv
         g6dqQiWhcNgOMfH1uQmR7L+kE5IcLSB2Mz493WTCTB84KwO3Rk1cmuIopRV++FoddFBT
         1aW64BJofFPk1pQeKhRpJ/KL9c6Vug+Tu1owq/ZfKx7qYim51VncYEkSK8ZGzOa0S8wk
         K8tbwv71xeEiP2UDilL0iX7zPAtKkDwoCdEjv6LOMHAw7+XoWRecG2YlpLZCp+MR3AQJ
         u9rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qr0RgZ+a/zM+SxkgK8YQOOF3fimOwozA4DwLbZMc1d4=;
        b=lCWyivTGAIF3ExIbQkrXcf56Yae6vocJC2+PYhzhV/MlUimphUc1Ef3MT2k15KiuiZ
         VpfWhtCUNjEMGP4kU6O16gWJfsWirk5nhZNAxPF3LTZqx2cq46w6QYKOjwtp84zKBd0s
         wMtRB17Azs7OJDJDOhKSSTSbX8ZcQKxvSHGu1YyHq8jwqp8Rt+yXvCkDbxV4eF3l0GTn
         WIs3/x2Q3RwdKj/lrTjjvN11drR5Cw313TXaMjrx+fnOnr0Gp2OMMOSvgHdOFm2PtiGm
         fl7brh4lBbePF1jrm81N4e0L5d+Hl0TN3TjQlRimjQLEAVEiVB4TJ9GVubSun42vq3Cv
         0H+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUbZ7DyJla02gMPLvUOmC8WDl6JQxiHV35GNQDyVHKdJErLRzjP
	GhY1OLmLHPDsCJLUzxKgmy8=
X-Google-Smtp-Source: APXvYqy0h+093Nv9MbSsqjeVDWbq+nQFhqYhfvo2eYJJbNGm7i0l1F2mqc5Cz7Hs6IfMQAQQtb5Rew==
X-Received: by 2002:a2e:9143:: with SMTP id q3mr9596549ljg.199.1575653550595;
        Fri, 06 Dec 2019 09:32:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c74d:: with SMTP id x74ls739290lff.12.gmail; Fri, 06 Dec
 2019 09:32:30 -0800 (PST)
X-Received: by 2002:ac2:4c31:: with SMTP id u17mr8635837lfq.57.1575653550077;
        Fri, 06 Dec 2019 09:32:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575653550; cv=none;
        d=google.com; s=arc-20160816;
        b=ZyVpdL8vFyxjpWJnZ8/oqRU7r8EBnaQ1t4TCkiDXFU38AHGXy2DNAqpyxKVt/FnBGi
         v4vt60HFBTzhPqMrM6hLuhx2mUhsW+fP7CL4dcRTMDp8MQfQpZe68k8oITSPijRx1Otc
         5VN7Bdpis9QrfhwTrDsthUg08fT8oYcFg3StTzOsjB89OgOcszRUqm6o+OxoIhiqjUFe
         XimaWriT0jikhvZxrFyluB8gkhT5CKNnergNgCh8Sg/gYZvmXSGE3z6dlfY2KDdzJgmJ
         2uCPbBBPK8/XEWZKh+1Yg2DTEJFjn7j/52wIhtZfGCh1D53cvNVGhb2loMbr7AgMMbnn
         51ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=i/QmWVEp5u71jRLoJFEe66MhYXylnknKFGBSZjbxrQY=;
        b=AkTxok55E8s/U2DsVrH9t1BuUTOXkBfkpnb34799/GAUAnUcUUyCqEKAs64jhK3v/T
         9xzpYXCpMbETMFW7JQdR+B2rgS/ho9pYKVgZDzmzqs9Zwn6gLNVKw+sqEvYJjKD3aJ/7
         /f+MRdff/PSiopJ424H2SX7dfslHbOUfx5Q/WR0TCDyxK7MX0YQ8LLh1wyUgu7Hl5heH
         FrZgyHxzYOXjPqKLw1ZLQGkV0zNB1skQIfme550dHGWitzflWQ1kPP0MZJ7TIm1x5o4j
         wtEwhLZ0EfZgIQGlCJCZlfL0prSBeufFrtlNbqCi9osBaH7e0er9tyTURweA10YpJXN+
         OlYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rzTAITx7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id u5si765741lfm.0.2019.12.06.09.32.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Dec 2019 09:32:30 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id c19so8438594lji.11
        for <kasan-dev@googlegroups.com>; Fri, 06 Dec 2019 09:32:30 -0800 (PST)
X-Received: by 2002:a05:651c:2046:: with SMTP id t6mr8198073ljo.180.1575653549568;
        Fri, 06 Dec 2019 09:32:29 -0800 (PST)
Received: from pc636 ([37.139.158.167])
        by smtp.gmail.com with ESMTPSA id e14sm7958952ljj.36.2019.12.06.09.32.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2019 09:32:28 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 6 Dec 2019 18:32:21 +0100
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: fix crashes on access to memory mapped by
 vm_map_ram()
Message-ID: <20191206173221.GA9500@pc636>
References: <20191204224037.GA12896@pc636>
 <20191205095942.1761-1-aryabinin@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191205095942.1761-1-aryabinin@virtuozzo.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=rzTAITx7;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::243 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 05, 2019 at 12:59:42PM +0300, Andrey Ryabinin wrote:
> With CONFIG_KASAN_VMALLOC=y any use of memory obtained via vm_map_ram()
> will crash because there is no shadow backing that memory.
> 
> Instead of sprinkling additional kasan_populate_vmalloc() calls all over
> the vmalloc code, move it into alloc_vmap_area(). This will fix
> vm_map_ram() and simplify the code a bit.
> 
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> ---
> 
>  Changes since v1:
>   - Fix error path in alloc_vmap_area.
>   - Remove wrong Reported-by: syzbot (The issue reported by bot is a different one)
> 
>  include/linux/kasan.h | 15 +++++---
>  mm/kasan/common.c     | 27 +++++++++-----
>  mm/vmalloc.c          | 85 ++++++++++++++++++++-----------------------
>  3 files changed, 67 insertions(+), 60 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 4f404c565db1..e18fe54969e9 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -205,20 +205,23 @@ static inline void *kasan_reset_tag(const void *addr)
>  #endif /* CONFIG_KASAN_SW_TAGS */
>  
>  #ifdef CONFIG_KASAN_VMALLOC
> -int kasan_populate_vmalloc(unsigned long requested_size,
> -			   struct vm_struct *area);
> -void kasan_poison_vmalloc(void *start, unsigned long size);
> +int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
> +void kasan_poison_vmalloc(const void *start, unsigned long size);
> +void kasan_unpoison_vmalloc(const void *start, unsigned long size);
>  void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  			   unsigned long free_region_start,
>  			   unsigned long free_region_end);
>  #else
> -static inline int kasan_populate_vmalloc(unsigned long requested_size,
> -					 struct vm_struct *area)
> +static inline int kasan_populate_vmalloc(unsigned long start,
> +					unsigned long size)
>  {
>  	return 0;
>  }
>  
> -static inline void kasan_poison_vmalloc(void *start, unsigned long size) {}
> +static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
> +{ }
> +static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> +{ }
>  static inline void kasan_release_vmalloc(unsigned long start,
>  					 unsigned long end,
>  					 unsigned long free_region_start,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index df3371d5c572..a1e6273be8c3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -777,15 +777,17 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  	return 0;
>  }
>  
> -int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
> +int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>  {
>  	unsigned long shadow_start, shadow_end;
>  	int ret;
>  
> -	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
> +	if (!is_vmalloc_or_module_addr((void *)addr))
> +		return 0;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
>  	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> -	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr +
> -							area->size);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
>  	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
>  
>  	ret = apply_to_page_range(&init_mm, shadow_start,
> @@ -796,10 +798,6 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
>  
>  	flush_cache_vmap(shadow_start, shadow_end);
>  
> -	kasan_unpoison_shadow(area->addr, requested_size);
> -
> -	area->flags |= VM_KASAN;
> -
>  	/*
>  	 * We need to be careful about inter-cpu effects here. Consider:
>  	 *
> @@ -842,12 +840,23 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
>   * Poison the shadow for a vmalloc region. Called as part of the
>   * freeing process at the time the region is freed.
>   */
> -void kasan_poison_vmalloc(void *start, unsigned long size)
> +void kasan_poison_vmalloc(const void *start, unsigned long size)
>  {
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
>  	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
>  	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
>  }
>  
> +void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> +{
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
> +	kasan_unpoison_shadow(start, size);
> +}
> +
>  static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  					void *unused)
>  {
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 4d3b3d60d893..6e865cea846c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1061,6 +1061,26 @@ __alloc_vmap_area(unsigned long size, unsigned long align,
>  	return nva_start_addr;
>  }
>  
> +/*
> + * Free a region of KVA allocated by alloc_vmap_area
> + */
> +static void free_vmap_area(struct vmap_area *va)
> +{
> +	/*
> +	 * Remove from the busy tree/list.
> +	 */
> +	spin_lock(&vmap_area_lock);
> +	unlink_va(va, &vmap_area_root);
> +	spin_unlock(&vmap_area_lock);
> +
> +	/*
> +	 * Insert/Merge it back to the free tree/list.
> +	 */
> +	spin_lock(&free_vmap_area_lock);
> +	merge_or_add_vmap_area(va, &free_vmap_area_root, &free_vmap_area_list);
> +	spin_unlock(&free_vmap_area_lock);
> +}
> +
>  /*
>   * Allocate a region of KVA of the specified size and alignment, within the
>   * vstart and vend.
> @@ -1073,6 +1093,7 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  	struct vmap_area *va, *pva;
>  	unsigned long addr;
>  	int purged = 0;
> +	int ret;
>  
>  	BUG_ON(!size);
>  	BUG_ON(offset_in_page(size));
> @@ -1139,6 +1160,7 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  	va->va_end = addr + size;
>  	va->vm = NULL;
>  
> +
>  	spin_lock(&vmap_area_lock);
>  	insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
>  	spin_unlock(&vmap_area_lock);
> @@ -1147,6 +1169,12 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  	BUG_ON(va->va_start < vstart);
>  	BUG_ON(va->va_end > vend);
>  
> +	ret = kasan_populate_vmalloc(addr, size);
> +	if (ret) {
> +		free_vmap_area(va);
> +		return ERR_PTR(ret);
> +	}
> +
>  	return va;
>  
>  overflow:
> @@ -1185,26 +1213,6 @@ int unregister_vmap_purge_notifier(struct notifier_block *nb)
>  }
>  EXPORT_SYMBOL_GPL(unregister_vmap_purge_notifier);
>  
> -/*
> - * Free a region of KVA allocated by alloc_vmap_area
> - */
> -static void free_vmap_area(struct vmap_area *va)
> -{
> -	/*
> -	 * Remove from the busy tree/list.
> -	 */
> -	spin_lock(&vmap_area_lock);
> -	unlink_va(va, &vmap_area_root);
> -	spin_unlock(&vmap_area_lock);
> -
> -	/*
> -	 * Insert/Merge it back to the free tree/list.
> -	 */
> -	spin_lock(&free_vmap_area_lock);
> -	merge_or_add_vmap_area(va, &free_vmap_area_root, &free_vmap_area_list);
> -	spin_unlock(&free_vmap_area_lock);
> -}
> -
>  /*
>   * Clear the pagetable entries of a given vmap_area
>   */
> @@ -1771,6 +1779,8 @@ void vm_unmap_ram(const void *mem, unsigned int count)
>  	BUG_ON(addr > VMALLOC_END);
>  	BUG_ON(!PAGE_ALIGNED(addr));
>  
> +	kasan_poison_vmalloc(mem, size);
> +
>  	if (likely(count <= VMAP_MAX_ALLOC)) {
>  		debug_check_no_locks_freed(mem, size);
>  		vb_free(mem, size);
> @@ -1821,6 +1831,9 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
>  		addr = va->va_start;
>  		mem = (void *)addr;
>  	}
> +
> +	kasan_unpoison_vmalloc(mem, size);
> +
>  	if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
>  		vm_unmap_ram(mem, count);
>  		return NULL;
> @@ -2075,6 +2088,7 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>  {
>  	struct vmap_area *va;
>  	struct vm_struct *area;
> +	unsigned long requested_size = size;
>  
>  	BUG_ON(in_interrupt());
>  	size = PAGE_ALIGN(size);
> @@ -2098,23 +2112,9 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>  		return NULL;
>  	}
>  
> -	setup_vmalloc_vm(area, va, flags, caller);
> +	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
>  
> -	/*
> -	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
> -	 * area with real memory. If we come here through VM_ALLOC, this is
> -	 * done by a higher level function that has access to the true size,
> -	 * which might not be a full page.
> -	 *
> -	 * We assume module space comes via VM_ALLOC path.
> -	 */
> -	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
> -		if (kasan_populate_vmalloc(area->size, area)) {
> -			unmap_vmap_area(va);
> -			kfree(area);
> -			return NULL;
> -		}
> -	}
> +	setup_vmalloc_vm(area, va, flags, caller);
>  
>  	return area;
>  }
> @@ -2293,8 +2293,7 @@ static void __vunmap(const void *addr, int deallocate_pages)
>  	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>  	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>  
> -	if (area->flags & VM_KASAN)
> -		kasan_poison_vmalloc(area->addr, area->size);
> +	kasan_poison_vmalloc(area->addr, area->size);
>  
>  	vm_remove_mappings(area, deallocate_pages);
>  
> @@ -2539,7 +2538,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	if (!size || (size >> PAGE_SHIFT) > totalram_pages())
>  		goto fail;
>  
> -	area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
> +	area = __get_vm_area_node(real_size, align, VM_ALLOC | VM_UNINITIALIZED |
>  				vm_flags, start, end, node, gfp_mask, caller);
>  	if (!area)
>  		goto fail;
> @@ -2548,11 +2547,6 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	if (!addr)
>  		return NULL;
>  
> -	if (is_vmalloc_or_module_addr(area->addr)) {
> -		if (kasan_populate_vmalloc(real_size, area))
> -			return NULL;
> -	}
> -
>  	/*
>  	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>  	 * flag. It means that vm_struct is not fully initialized.
> @@ -3437,7 +3431,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	/* populate the shadow space outside of the lock */
>  	for (area = 0; area < nr_vms; area++) {
>  		/* assume success here */
> -		kasan_populate_vmalloc(sizes[area], vms[area]);
> +		kasan_populate_vmalloc(vas[area]->va_start, sizes[area]);
> +		kasan_unpoison_vmalloc((void *)vms[area]->addr, sizes[area]);
>  	}
>  
>  	kfree(vas);
> -- 
> 2.23.0
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>

--
Vlad Rezki
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191206173221.GA9500%40pc636.
