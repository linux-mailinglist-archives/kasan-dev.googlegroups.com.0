Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBFNSYSVQMGQEUFD2WNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A705807D79
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 02:00:07 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4255d2557easf3699141cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 17:00:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701910806; cv=pass;
        d=google.com; s=arc-20160816;
        b=NSJeFkLZLYqCyhgn107IZpSd6tiFXNW4/pp3ahoe2A58Sx4jpx2tcNt8ojt1rdxh+b
         lOZq5gTWnx8qmUU7zo9M7rBi6XLYTiBBmw0WAOg1XhVSGfUAKNTxaPmYNpqPBqPECkZ/
         KedPUsZR3UdYpOLtCYNCD4tUI/etvU8lAGmPrxHzQQwm+c0hhCa89VnCiTaEpaceOYpN
         TPNEFf/L/7pAhcw3gATPgTHx4s3JNCq5Iiddv5+BRsaRn2yzpHUBuyVYZmtXFT2N5DD+
         7ptNLNidGYZWj9gSpvrlYr01NLsQSUxEOBnYThdAEwr64VmxO0lcBnmushK90ErlG5GB
         geaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=v7Q5Nv4lFnn2ZEkhf8g0UvXb8SBb42sNLYcmykT4X+o=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=gfpiEgarhrOBenJztrx7MJcTApo8z2CAzT9o7dZ7zfZqL4KXy5PBdGF4l5HjeN4Xpe
         b4oQu9q458n8+3bL9+CIi8vVkuMLTD3VwGK+Mj3M98mYOYw0Nf/QslQw7CpKZEi0r33J
         NicwjM1UNtvX51okto47C1191nhlodVQ6IUmOBsoJAHH8coPTkJU9gT9ori7LnBz9IE3
         Um29baOjwyovY7afmv6zN6HvMZ+gkMwAhCvOOtSzbys284O6BQHLEjTVkZhTaD5e66Dy
         mjjVq2RJ9zePTEjXo/r3whzRi5PXlOhIBzQN0TY7kF2okNAxQX8Y45seXFZ0pbfPec8U
         FMfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ePghrvAp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701910806; x=1702515606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v7Q5Nv4lFnn2ZEkhf8g0UvXb8SBb42sNLYcmykT4X+o=;
        b=B0/HKgPj8YG2fUspwv3Al5KygCtU0sUIVpXizX2uvZPEqFghdGIxTNXN708h2ld9EO
         Dy2ytUOV9tdilGXH1X3AheXAWBKydo18fRireiWNYQYPw+gabdM7cCKQMKTmH3ntaY0N
         Oe57rJ8yunyHrI15hbEsXrnU2AMz4oRLWQ7246s5chVTYDZpTtyxvzf2SbbQGVx8YYeV
         aJU+KvUUxGG9I4mrtfkFxz1jHgC59a/NKcDbMy8pMFV/dlIvxQagyRVW+0oEqjC/8dza
         dDGv1FG1KLinx5Ruyhlb50fwlefk9c4L3ZDUCBLDX6D25xZFB//wwu1cfuIsG63k5tr4
         tahg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701910806; x=1702515606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=v7Q5Nv4lFnn2ZEkhf8g0UvXb8SBb42sNLYcmykT4X+o=;
        b=WoO+s0M+nXo1Ri/He4+pcsYkJnAuBntQD+D0STJXR04dKYbJS1rKGv39L6Xn3KbEo1
         N72ZUEfMFWB07/j9ZFdQO+caFFEqnuz8tn3izCNSbB15r1uf7p/stanUi0lASLo9XsHy
         oOT5nLMxgsRcwM19YxIR+jMHltM7Ci3xzi+1m9KdvRKzs3oTQgQbL9cxiQqElmDVMZ2M
         foIPP7iEOZsYPhQ4/M2Tj7Y2mtP4g1nyx5NiFyycgNUIHQ4tD0/kPyfFYNZT/ETvTPMw
         I/7GEOMOov+M5ggxr1hC3H9IbWQP/M3m0iFz/Y0rxmcxvQ367VC0oJYAjCj/lWcvHQn/
         EyMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701910806; x=1702515606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v7Q5Nv4lFnn2ZEkhf8g0UvXb8SBb42sNLYcmykT4X+o=;
        b=Vq1fX9B3Za0vPy7VgByFkk0hwfz1cFOHW1lupJ3UOfmFGvjST6DzYS3TUwLK7YIa6O
         bbg4a4wUA48fsQNVDxX8vFi0lKo2I7LYaSI/WX1EYd6zYoM+mGLtWL8G417sdI1NfHO8
         U/8W3SZRLSFq8h0HNdk4LNAPqyXzmbZfAFKkPCGvOIN3yVPrbXvXNopDmbFCbXjMuwYu
         5Rk7yx3kKthylq1LWNekVY/bnYiqoB1VuHZkN2cjTZ5YjKV65tPISavbz4GZ+QVboO9/
         jZiBRGFhRZ8yCfGuXobn2/BC9ckXo3baTTsydi4773q0ILQS2VQGjDj4vK99ZlgD5WUZ
         PBmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwaROw2juKTJMe25iw+U6S857sKCyHH4wpzzoL9rPABF77OpKIp
	yELKSPxUt7df2oFU4b9k3ao=
X-Google-Smtp-Source: AGHT+IEnVaa/RYId/CXL2oJ1jRLdNV0fS0kf2q3mWiJlEUfbXv1DFAjZEa/h1/H1BFoIEYIAfH9SLQ==
X-Received: by 2002:ac8:58d2:0:b0:423:9b25:3943 with SMTP id u18-20020ac858d2000000b004239b253943mr2368876qta.65.1701910805702;
        Wed, 06 Dec 2023 17:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:102:b0:423:8c6b:503a with SMTP id
 u2-20020a05622a010200b004238c6b503als428302qtw.1.-pod-prod-07-us; Wed, 06 Dec
 2023 17:00:04 -0800 (PST)
X-Received: by 2002:ac8:7c47:0:b0:425:4043:762f with SMTP id o7-20020ac87c47000000b004254043762fmr2230355qtv.87.1701910804629;
        Wed, 06 Dec 2023 17:00:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701910804; cv=none;
        d=google.com; s=arc-20160816;
        b=wEUcETWJ+PlaqDTJzc4Z029uftAEX2oJ6vhXmofr8fAWyoZ2ZrjylGfGqSMknA/6NY
         eA4T9atEld3DX/CmZ0t4V0u1bD1Xy0KqPHuuJqV7rWL44p3Gq+/cnKqrHvPM3cNxYaST
         5kOBjOmqDqSzF0KEWjq8lXr3Y94ZtQjsWDDFfV5WyBGYOVVpprwIxkVcZu8Hx18U8Oe+
         72+VvfAbRZMLKu9ZhqohCMP7LOmdxH8tzkOQxCH5xYbtA1/p4A/AsxgMlriSVOosNrno
         BIJlGrNHykCVc80Gq1HXbrRI3qrTpyiQK3Xm1YDWAZoj9p6A3oajQpmjUQE9BJwh9Gq0
         HCLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zsGIjCFU5lyJ4K017s44uK87gjwXDiMcgnBYCQQOfWs=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=GgkHXbP4CrhEr9xYripNUh8seHOelGYQAcAyHmUzBI2avLJTW1fMQIqwcibOAxVJ94
         VjIAWDxmoKu2rJw8y01+1B3XeNl0H1bW0oXRAtwJcfYR2uDZcoy+Y3WgZ/rDigK2ulq/
         qLZpfmWyHkUuJ2b3bNMQAmiTY0MFE8x/ydsR+vVk9dXTR3IEM0ywCuj3GJB4oQuQakqr
         8zfKtLFYYmgyLYUC0W8VBu1Noqqcng28upFt9EalfiTAHym6ESoytT3gUoeiAfSERa1z
         rrmcSUv52lwSmG4W0/5Nsxm7Bij0wNDQ1AuCHjScbFu289D68DcYOM4KvWjvM2gsHEdV
         clvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ePghrvAp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id cq7-20020a05622a424700b00423f3ace78asi70956qtb.4.2023.12.06.17.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 17:00:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1d0c93b1173so2749105ad.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 17:00:04 -0800 (PST)
X-Received: by 2002:a17:903:2642:b0:1d0:6ffd:f214 with SMTP id je2-20020a170903264200b001d06ffdf214mr1476793plb.106.1701910803148;
        Wed, 06 Dec 2023 17:00:03 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id b6-20020a170902bd4600b001d0af279a1fsm70671plx.182.2023.12.06.16.59.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 17:00:02 -0800 (PST)
Date: Thu, 7 Dec 2023 09:59:46 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org,
	Michal Hocko <mhocko@suse.com>
Subject: Re: [PATCH v2 14/21] mm/slab: move memcg related functions from
 slab.h to slub.c
Message-ID: <ZXEZAnHBJpAi8Sdy@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-14-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-14-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ePghrvAp;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:25PM +0100, Vlastimil Babka wrote:
> We don't share those between SLAB and SLUB anymore, so most memcg
> related functions can be moved to slub.c proper.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Acked-by: Michal Hocko <mhocko@suse.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h | 206 --------------------------------------------------------------
>  mm/slub.c | 205 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
>  2 files changed, 205 insertions(+), 206 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 65ebf86b3fe9..a81ef7c9282d 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -486,12 +486,6 @@ void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *s);
>  ssize_t slabinfo_write(struct file *file, const char __user *buffer,
>  		       size_t count, loff_t *ppos);
>  
> -static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
> -{
> -	return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
> -		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
> -}
> -
>  #ifdef CONFIG_SLUB_DEBUG
>  #ifdef CONFIG_SLUB_DEBUG_ON
>  DECLARE_STATIC_KEY_TRUE(slub_debug_enabled);
> @@ -551,220 +545,20 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
>  				 gfp_t gfp, bool new_slab);
>  void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
>  		     enum node_stat_item idx, int nr);
> -
> -static inline void memcg_free_slab_cgroups(struct slab *slab)
> -{
> -	kfree(slab_objcgs(slab));
> -	slab->memcg_data = 0;
> -}
> -
> -static inline size_t obj_full_size(struct kmem_cache *s)
> -{
> -	/*
> -	 * For each accounted object there is an extra space which is used
> -	 * to store obj_cgroup membership. Charge it too.
> -	 */
> -	return s->size + sizeof(struct obj_cgroup *);
> -}
> -
> -/*
> - * Returns false if the allocation should fail.
> - */
> -static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> -					     struct list_lru *lru,
> -					     struct obj_cgroup **objcgp,
> -					     size_t objects, gfp_t flags)
> -{
> -	struct obj_cgroup *objcg;
> -
> -	if (!memcg_kmem_online())
> -		return true;
> -
> -	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
> -		return true;
> -
> -	/*
> -	 * The obtained objcg pointer is safe to use within the current scope,
> -	 * defined by current task or set_active_memcg() pair.
> -	 * obj_cgroup_get() is used to get a permanent reference.
> -	 */
> -	objcg = current_obj_cgroup();
> -	if (!objcg)
> -		return true;
> -
> -	if (lru) {
> -		int ret;
> -		struct mem_cgroup *memcg;
> -
> -		memcg = get_mem_cgroup_from_objcg(objcg);
> -		ret = memcg_list_lru_alloc(memcg, lru, flags);
> -		css_put(&memcg->css);
> -
> -		if (ret)
> -			return false;
> -	}
> -
> -	if (obj_cgroup_charge(objcg, flags, objects * obj_full_size(s)))
> -		return false;
> -
> -	*objcgp = objcg;
> -	return true;
> -}
> -
> -static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
> -					      struct obj_cgroup *objcg,
> -					      gfp_t flags, size_t size,
> -					      void **p)
> -{
> -	struct slab *slab;
> -	unsigned long off;
> -	size_t i;
> -
> -	if (!memcg_kmem_online() || !objcg)
> -		return;
> -
> -	for (i = 0; i < size; i++) {
> -		if (likely(p[i])) {
> -			slab = virt_to_slab(p[i]);
> -
> -			if (!slab_objcgs(slab) &&
> -			    memcg_alloc_slab_cgroups(slab, s, flags,
> -							 false)) {
> -				obj_cgroup_uncharge(objcg, obj_full_size(s));
> -				continue;
> -			}
> -
> -			off = obj_to_index(s, slab, p[i]);
> -			obj_cgroup_get(objcg);
> -			slab_objcgs(slab)[off] = objcg;
> -			mod_objcg_state(objcg, slab_pgdat(slab),
> -					cache_vmstat_idx(s), obj_full_size(s));
> -		} else {
> -			obj_cgroup_uncharge(objcg, obj_full_size(s));
> -		}
> -	}
> -}
> -
> -static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> -					void **p, int objects)
> -{
> -	struct obj_cgroup **objcgs;
> -	int i;
> -
> -	if (!memcg_kmem_online())
> -		return;
> -
> -	objcgs = slab_objcgs(slab);
> -	if (!objcgs)
> -		return;
> -
> -	for (i = 0; i < objects; i++) {
> -		struct obj_cgroup *objcg;
> -		unsigned int off;
> -
> -		off = obj_to_index(s, slab, p[i]);
> -		objcg = objcgs[off];
> -		if (!objcg)
> -			continue;
> -
> -		objcgs[off] = NULL;
> -		obj_cgroup_uncharge(objcg, obj_full_size(s));
> -		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
> -				-obj_full_size(s));
> -		obj_cgroup_put(objcg);
> -	}
> -}
> -
>  #else /* CONFIG_MEMCG_KMEM */
>  static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
>  {
>  	return NULL;
>  }
>  
> -static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
> -{
> -	return NULL;
> -}
> -
>  static inline int memcg_alloc_slab_cgroups(struct slab *slab,
>  					       struct kmem_cache *s, gfp_t gfp,
>  					       bool new_slab)
>  {
>  	return 0;
>  }
> -
> -static inline void memcg_free_slab_cgroups(struct slab *slab)
> -{
> -}
> -
> -static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> -					     struct list_lru *lru,
> -					     struct obj_cgroup **objcgp,
> -					     size_t objects, gfp_t flags)
> -{
> -	return true;
> -}
> -
> -static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
> -					      struct obj_cgroup *objcg,
> -					      gfp_t flags, size_t size,
> -					      void **p)
> -{
> -}
> -
> -static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> -					void **p, int objects)
> -{
> -}
>  #endif /* CONFIG_MEMCG_KMEM */
>  
> -static inline struct kmem_cache *virt_to_cache(const void *obj)
> -{
> -	struct slab *slab;
> -
> -	slab = virt_to_slab(obj);
> -	if (WARN_ONCE(!slab, "%s: Object is not a Slab page!\n",
> -					__func__))
> -		return NULL;
> -	return slab->slab_cache;
> -}
> -
> -static __always_inline void account_slab(struct slab *slab, int order,
> -					 struct kmem_cache *s, gfp_t gfp)
> -{
> -	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
> -		memcg_alloc_slab_cgroups(slab, s, gfp, true);
> -
> -	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> -			    PAGE_SIZE << order);
> -}
> -
> -static __always_inline void unaccount_slab(struct slab *slab, int order,
> -					   struct kmem_cache *s)
> -{
> -	if (memcg_kmem_online())
> -		memcg_free_slab_cgroups(slab);
> -
> -	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> -			    -(PAGE_SIZE << order));
> -}
> -
> -static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
> -{
> -	struct kmem_cache *cachep;
> -
> -	if (!IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
> -	    !kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS))
> -		return s;
> -
> -	cachep = virt_to_cache(x);
> -	if (WARN(cachep && cachep != s,
> -		  "%s: Wrong slab cache. %s but object is from %s\n",
> -		  __func__, s->name, cachep->name))
> -		print_tracking(cachep, x);
> -	return cachep;
> -}
> -
>  void free_large_kmalloc(struct folio *folio, void *object);
>  
>  size_t __ksize(const void *objp);
> diff --git a/mm/slub.c b/mm/slub.c
> index 9eb6508152c2..844e0beb84ee 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1814,6 +1814,165 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
>  #endif
>  #endif /* CONFIG_SLUB_DEBUG */
>  
> +static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
> +{
> +	return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
> +		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
> +}
> +
> +#ifdef CONFIG_MEMCG_KMEM
> +static inline void memcg_free_slab_cgroups(struct slab *slab)
> +{
> +	kfree(slab_objcgs(slab));
> +	slab->memcg_data = 0;
> +}
> +
> +static inline size_t obj_full_size(struct kmem_cache *s)
> +{
> +	/*
> +	 * For each accounted object there is an extra space which is used
> +	 * to store obj_cgroup membership. Charge it too.
> +	 */
> +	return s->size + sizeof(struct obj_cgroup *);
> +}
> +
> +/*
> + * Returns false if the allocation should fail.
> + */
> +static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> +					     struct list_lru *lru,
> +					     struct obj_cgroup **objcgp,
> +					     size_t objects, gfp_t flags)
> +{
> +	struct obj_cgroup *objcg;
> +
> +	if (!memcg_kmem_online())
> +		return true;
> +
> +	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
> +		return true;
> +
> +	/*
> +	 * The obtained objcg pointer is safe to use within the current scope,
> +	 * defined by current task or set_active_memcg() pair.
> +	 * obj_cgroup_get() is used to get a permanent reference.
> +	 */
> +	objcg = current_obj_cgroup();
> +	if (!objcg)
> +		return true;
> +
> +	if (lru) {
> +		int ret;
> +		struct mem_cgroup *memcg;
> +
> +		memcg = get_mem_cgroup_from_objcg(objcg);
> +		ret = memcg_list_lru_alloc(memcg, lru, flags);
> +		css_put(&memcg->css);
> +
> +		if (ret)
> +			return false;
> +	}
> +
> +	if (obj_cgroup_charge(objcg, flags, objects * obj_full_size(s)))
> +		return false;
> +
> +	*objcgp = objcg;
> +	return true;
> +}
> +
> +static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
> +					      struct obj_cgroup *objcg,
> +					      gfp_t flags, size_t size,
> +					      void **p)
> +{
> +	struct slab *slab;
> +	unsigned long off;
> +	size_t i;
> +
> +	if (!memcg_kmem_online() || !objcg)
> +		return;
> +
> +	for (i = 0; i < size; i++) {
> +		if (likely(p[i])) {
> +			slab = virt_to_slab(p[i]);
> +
> +			if (!slab_objcgs(slab) &&
> +			    memcg_alloc_slab_cgroups(slab, s, flags, false)) {
> +				obj_cgroup_uncharge(objcg, obj_full_size(s));
> +				continue;
> +			}
> +
> +			off = obj_to_index(s, slab, p[i]);
> +			obj_cgroup_get(objcg);
> +			slab_objcgs(slab)[off] = objcg;
> +			mod_objcg_state(objcg, slab_pgdat(slab),
> +					cache_vmstat_idx(s), obj_full_size(s));
> +		} else {
> +			obj_cgroup_uncharge(objcg, obj_full_size(s));
> +		}
> +	}
> +}
> +
> +static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +					void **p, int objects)
> +{
> +	struct obj_cgroup **objcgs;
> +	int i;
> +
> +	if (!memcg_kmem_online())
> +		return;
> +
> +	objcgs = slab_objcgs(slab);
> +	if (!objcgs)
> +		return;
> +
> +	for (i = 0; i < objects; i++) {
> +		struct obj_cgroup *objcg;
> +		unsigned int off;
> +
> +		off = obj_to_index(s, slab, p[i]);
> +		objcg = objcgs[off];
> +		if (!objcg)
> +			continue;
> +
> +		objcgs[off] = NULL;
> +		obj_cgroup_uncharge(objcg, obj_full_size(s));
> +		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
> +				-obj_full_size(s));
> +		obj_cgroup_put(objcg);
> +	}
> +}
> +#else /* CONFIG_MEMCG_KMEM */
> +static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
> +{
> +	return NULL;
> +}
> +
> +static inline void memcg_free_slab_cgroups(struct slab *slab)
> +{
> +}
> +
> +static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> +					     struct list_lru *lru,
> +					     struct obj_cgroup **objcgp,
> +					     size_t objects, gfp_t flags)
> +{
> +	return true;
> +}
> +
> +static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
> +					      struct obj_cgroup *objcg,
> +					      gfp_t flags, size_t size,
> +					      void **p)
> +{
> +}
> +
> +static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +					void **p, int objects)
> +{
> +}
> +#endif /* CONFIG_MEMCG_KMEM */
> +
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typical
>   * production configuration these hooks all should produce no code at all.
> @@ -2048,6 +2207,26 @@ static inline bool shuffle_freelist(struct kmem_cache *s, struct slab *slab)
>  }
>  #endif /* CONFIG_SLAB_FREELIST_RANDOM */
>  
> +static __always_inline void account_slab(struct slab *slab, int order,
> +					 struct kmem_cache *s, gfp_t gfp)
> +{
> +	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
> +		memcg_alloc_slab_cgroups(slab, s, gfp, true);
> +
> +	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> +			    PAGE_SIZE << order);
> +}
> +
> +static __always_inline void unaccount_slab(struct slab *slab, int order,
> +					   struct kmem_cache *s)
> +{
> +	if (memcg_kmem_online())
> +		memcg_free_slab_cgroups(slab);
> +
> +	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> +			    -(PAGE_SIZE << order));
> +}
> +
>  static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
>  {
>  	struct slab *slab;
> @@ -3965,6 +4144,32 @@ void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  }
>  #endif
>  
> +static inline struct kmem_cache *virt_to_cache(const void *obj)
> +{
> +	struct slab *slab;
> +
> +	slab = virt_to_slab(obj);
> +	if (WARN_ONCE(!slab, "%s: Object is not a Slab page!\n", __func__))
> +		return NULL;
> +	return slab->slab_cache;
> +}
> +
> +static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
> +{
> +	struct kmem_cache *cachep;
> +
> +	if (!IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
> +	    !kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS))
> +		return s;
> +
> +	cachep = virt_to_cache(x);
> +	if (WARN(cachep && cachep != s,
> +		 "%s: Wrong slab cache. %s but object is from %s\n",
> +		 __func__, s->name, cachep->name))
> +		print_tracking(cachep, x);
> +	return cachep;
> +}
> +
>  void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
>  {
>  	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
> 
> -- 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEZAnHBJpAi8Sdy%40localhost.localdomain.
