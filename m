Return-Path: <kasan-dev+bncBCJNVUGE34MBBXU253DQMGQEP6PWJ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7F07C06B2A
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 16:29:51 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4e88ddf3cd0sf65730791cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 07:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761316190; cv=pass;
        d=google.com; s=arc-20240605;
        b=GW1QZDtOztWQARk4Fk7yU1E31YazKnSFGfvi3tch3IjyW8Z9cuUcHc5+YWEC6HWHYK
         yAgL2epucruWKydKwyDka5t7d05JbfbDLLgwha325Uk6vZ/VguuYnEHB5VD/DvBe2hcA
         EVmGIbqiGrmQkGGvbSWpGhFMRRhLEVHg0+rqWFJWPxotVeflZhL3Sh3xpUB8ZrHk+4vm
         wMbi531DGR0N3tFY3hwJGJVrxQep6NvRJA0/PrIEZ121ZFMAHTNeAuI0iyMI/3wXHwZD
         5Ih6xCl8Jk2ndw8kZRcEbTIqfhmiPCeCXUH2/svRGy/nGgZ9RtKOsafgOyJn8/+cRFvO
         u0bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xhKErtCM87avueQ+MkZDLpNDhQ7uZNp/J6k+JkvHrN8=;
        fh=MB90gK/Z4dxq4ZAzt/aeZ0uC4wWSCaURaJRkcDB0Jrg=;
        b=cbbCFj3vyRGdXB1FUd1EOsAHjeV60aKij1XEJx1iBsEDOPkEAAD94eAYBuQ24hvjFa
         xHQ9Q2NcLWKr+CedZbaIE5yVu81i2GBmqIpGqvv31UDKXOSKfY8iuizy+Ll3OPfzVT8u
         ZvyL9J+w4GsDt+38Y2Xg9nLnlrA0a34GtJKlRAk4kpvN7V/LLCdOxPYl9GnRjFzcH452
         fCcHzkgv3KoUZw53vNmGTAyK2y2gsKRZTgIrAAvgTRxtKyR9iWNZaXnLW/mDNggLsUaQ
         zalNYe6waegaalz3OypVzIqIBNgx9ZjJL6wXeMOPJ/HMYBN7+3hOg3B1r+On7kY7Ovim
         /XOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=lNiDEF6C;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761316190; x=1761920990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xhKErtCM87avueQ+MkZDLpNDhQ7uZNp/J6k+JkvHrN8=;
        b=cECuknIZNm/mEvnD+P9a6DdfNcpa5/5ZaEEw+q25Rtp6JNg43u5G1vNTTNWgnOc4QY
         K4LGFSWWcsY8XdL85NCmxlD4soNpr5XDNL+EFj3JYDV7AVtrVUVKU2TtxxvR0FNyoL50
         za3vLzfvOVk1ZmYDb+pRjQCGN204mTKEk7idQLMWXT7P9l/oHFeYWxkKjcI3H8YwRvEy
         3+LMtTB0Jtw2sVqBnDr9v/abHeEI6mdNen3nY4jcIY+DnzLn4jFfNsO8ba99MJogsJtj
         QNQdMJcpaA6yofWOa0NclQuSrx7muWR5L7AqHVTL9EjC7jeObHTQzkCxWHFkdHS6zYXx
         xD5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761316190; x=1761920990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xhKErtCM87avueQ+MkZDLpNDhQ7uZNp/J6k+JkvHrN8=;
        b=UQtrZS3137XjKUoDoClCN6U0/tpF84uo0+cw48fa3+ERXa7XwWkOTGD0j56a4GudTV
         L4NOchM/LZh97gI04oh9PcFT8hqB61T5bDHfMGNyA45tuygALpT6Q1pmR9Ml/Q1lvpzA
         bND4yDMRab9srTYrDXxeAWHe+Aa5hQlR7FLYEnmzG4WEZkBciKXCkMD+r5NIC9wnaC3N
         FEXqqCFBjipZg+t3bwFLFCfdds/UF0A73IdFe9+TQV+E6/huIYQS/KS/AfKMoCDctdD+
         boSt9mMQS6iWplwfzQ7KYG2tfUMYMpt4xBMuThbDNj7CM5rJXvDWrwjk6Tt1nNwHcM4s
         CkeA==
X-Forwarded-Encrypted: i=2; AJvYcCW1Cal5Su69ComteRueG9GHGOw/wv+opSvmp1V1u35m9xTmb2YlvI2jcTXT7++EKf8mjdqMNQ==@lfdr.de
X-Gm-Message-State: AOJu0YyjBDcix7zUA+9vn98W4quSAtusQIjRETQ9h/Xh69VJfsvQ4uoD
	MEFFeKKzZNIgKuocp1zaukyhsTQNz/o9Sd9XjLfcfe2oWWT7hkrjUYoj
X-Google-Smtp-Source: AGHT+IEj26qiEwOWaVPiYO6JlvOd0Hv4Ia32acfNtp4Cn1JPN5+c1NG3Rjiz5+stgjSJ/Xn2NFcc+Q==
X-Received: by 2002:a05:622a:180e:b0:4e8:b0a9:d3d6 with SMTP id d75a77b69052e-4e8b0a9db45mr288832881cf.66.1761316190387;
        Fri, 24 Oct 2025 07:29:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4Nf15pRSBfCRZOzMMplUIjeaMRbtnfgfb6b4df65w1Sw=="
Received: by 2002:ac8:7d4b:0:b0:4d5:fa96:92b2 with SMTP id d75a77b69052e-4eb81594366ls8535801cf.1.-pod-prod-07-us;
 Fri, 24 Oct 2025 07:29:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVvV8zl0TDRFoylVUxmbkQ3c7f5n35GHYbZktyo/VLyBVJg+mD9ihHvg7knqWznUYJvEFfE4ozb2c=@googlegroups.com
X-Received: by 2002:ac8:5845:0:b0:4e8:b4a5:7f21 with SMTP id d75a77b69052e-4e8b4a5823amr272291561cf.46.1761316189055;
        Fri, 24 Oct 2025 07:29:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761316189; cv=none;
        d=google.com; s=arc-20240605;
        b=YTdzbd1D58aathdgNHeHCTZVAAoo3bZvaqIT6g5CNtS4SCPlFH+R/IzaqULGO5W2bA
         rZpAl5Nm7oLicZCDC8CCN/PQ0ynOeclVnxm96GXXC3iSoUCQAn5dKFIngq/qk2bbKl8S
         2R385THRFQFIcTi4r3b5Z/mWz5uvonJn03BxAbNb8/QqkFeK9sYEOUnqFC+4Le0C9u7G
         p8nCJPeQSzH4tEQW0wBQeht50CR3Zrg+39gVIiClwAgPhk949FBm7bSra4BiuP192Ojx
         ZRWCQYSbKGYZjzt5TC991MbJWcEJ7x6K8loTF18KUcgKXc9FqqmMgNJYlYRv1PeK8kXs
         vfJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6/h0G3p+CogW+KUD4A3h3rSaunnYLJugMgdAj9+txKM=;
        fh=bHAfn63gfa/6zgOaS4Q5hb17jvUVzDiE3LdJ4wZASA0=;
        b=iDGvj6W/BrwAsiG1cLkmcmlrIDmL1w3hy5omZ6XK1aubax1hnXCN/YbsoUCk5fe9yJ
         hqCf9Ebz9H0sF4kpHDxO9YfgEoAVilGUSeuODGYrmYGT4muotvYNDowMvJ2N72vXGTk+
         uqU8XST5OdzATqJBhTfHtdKJbpPQYwYak+pt53VbJlhce5SNjiB/xcs0Nt3MR2Haq4Zl
         6eRo359FPdW78rOao6mHCzGtOsnHueVmj3PYUYtU1M3NpZx9C86DPS2mWBY8FoLzrLwf
         rj96OPNf0gdOurPq6uXKWV+4NE+B85czPHuTQJyXjiLwPHfhpY+BIZRGD9dWvnk9Y9T8
         mM7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=lNiDEF6C;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87f9de7cb17si3086016d6.2.2025.10.24.07.29.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Oct 2025 07:29:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0044010.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 59O2UEjG1836665;
	Fri, 24 Oct 2025 07:29:45 -0700
Received: from maileast.thefacebook.com ([163.114.135.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 4a00qr3bp6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Fri, 24 Oct 2025 07:29:45 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c0a8:1b::8e35) by
 mail.thefacebook.com (2620:10d:c0a9:6f::8fd4) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Fri, 24 Oct 2025 14:29:44 +0000
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Chris Mason <clm@meta.com>, Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett"
	<Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        "Sebastian
 Andrzej Siewior" <bigeasy@linutronix.de>,
        Alexei Starovoitov
	<ast@kernel.org>, <linux-mm@kvack.org>,
        <linux-kernel@vger.kernel.org>, <linux-rt-devel@lists.linux.dev>,
        <bpf@vger.kernel.org>, <kasan-dev@googlegroups.com>
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from allocation paths
Date: Fri, 24 Oct 2025 07:29:20 -0700
Message-ID: <20251024142927.780367-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c0a8:1b::8e35]
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI0MDEyOSBTYWx0ZWRfXzo7mh/+QEEto
 lN48tJt90rZ0v9oBAvXPrAsfwe+CenqqyK68LR7o0BOfvJujTaqFIdwroPduE2PBMa7VnKqUE/B
 hR/lbf4iinufGfA1AoIc8lE3vKY7y4Hw5m21adIOtvFfDgLbh7c/rKrhMA+6RLDywjI9qT/AoPU
 QMz8k7g4r2r6F7d78Ky9USlLG/pqBLtW9jbItBaZRSJncw/ge9eg3eKLxO5qPcfnkt2yRAOGPDZ
 0oDHjSRBppMO5yVVZV2peChq0H2i7zjAjvg8Sie6K49tWvOlXv5+AOIWEC9CFAuuk3C2lzCpqtT
 +WAgDcHMs2kxxD4qDJk65eXaVVatHMy1wdEZjZIXRWbu9DTaF8gSAizL8JMHUtenNSM7KaKQCvX
 uRzKVvQvjM8o8dsWfoKrJwWlFoOyMA==
X-Authority-Analysis: v=2.4 cv=YfWwJgRf c=1 sm=1 tr=0 ts=68fb8d59 cx=c_pps
 a=MfjaFnPeirRr97d5FC5oHw==:117 a=MfjaFnPeirRr97d5FC5oHw==:17
 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22 a=Qud2Co-4zkO9aUnGrzwA:9
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-GUID: whmAAHXeJ-9g96VK63zLv5mAQoKsaiQB
X-Proofpoint-ORIG-GUID: whmAAHXeJ-9g96VK63zLv5mAQoKsaiQB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-24_02,2025-10-22_01,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=lNiDEF6C;       spf=pass
 (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42
 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On Thu, 23 Oct 2025 15:52:32 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
> 
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab().
> 
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
> 
> The rest of the changes is removing functions that no longer have any
> callers.
>

Hi Vlastimil,

We're trying out the AI patch review automation on the BPF commits and it had
some questions about a few of these.  Since the goal is to actually test the
automation, I'm putting them in unedited, but I did try and make sure they
were valid before sending.

This one seems pretty unlikely but still worth fixing:

>
> diff --git a/mm/slub.c b/mm/slub.c
> index e2b052657d11..bd67336e7c1f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c

[ ... ]

> @@ -3575,15 +3532,15 @@ static bool get_partial_node_bulk(struct kmem_cache *s,
>  }
>
>  /*
> - * Try to allocate a partial slab from a specific node.
> + * Try to allocate object from a partial slab on a specific node.
>   */
> -static struct slab *get_partial_node(struct kmem_cache *s,
> -				     struct kmem_cache_node *n,
> -				     struct partial_context *pc)
> +static void *get_partial_node(struct kmem_cache *s,
> +			      struct kmem_cache_node *n,
> +			      struct partial_context *pc)
>  {
> -	struct slab *slab, *slab2, *partial = NULL;
> +	struct slab *slab, *slab2;
>  	unsigned long flags;
> -	unsigned int partial_slabs = 0;
> +	void *object;
>
>  	/*
>  	 * Racy check. If we mistakenly see no partial slabs then we
> @@ -3599,54 +3556,54 @@ static struct slab *get_partial_node(struct kmem_cache *s,
>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>  		return NULL;
>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +
> +		unsigned long counters;
> +		struct slab new;
> +
>  		if (!pfmemalloc_match(slab, pc->flags))
>  			continue;

Can get_partial_node() return an uninitialized pointer? The variable
'object' is declared but never initialized. If all slabs in the partial
list fail the pfmemalloc_match() check, the loop completes without
setting 'object', then returns it at the end of the function.

In the previous version, the equivalent 'partial' variable was explicitly
initialized to NULL. When all slabs were skipped, NULL was returned.

>
>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> -			void *object = alloc_single_from_partial(s, n, slab,
> +			object = alloc_single_from_partial(s, n, slab,
>  							pc->orig_size);
> -			if (object) {
> -				partial = slab;
> -				pc->object = object;
> +			if (object)
>  				break;
> -			}
>  			continue;
>  		}
>
> -		remove_partial(n, slab);
> -
> -		if (!partial) {
> -			partial = slab;
> -			stat(s, ALLOC_FROM_PARTIAL);
> -
> -			if ((slub_get_cpu_partial(s) == 0)) {
> -				break;
> -			}
> -		} else {
> -			put_cpu_partial(s, slab, 0);
> -			stat(s, CPU_PARTIAL_NODE);
> -
> -			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
> -				break;
> -			}
> -		}
> +		/*
> +		 * get a single object from the slab. This might race against
> +		 * __slab_free(), which however has to take the list_lock if
> +		 * it's about to make the slab fully free.
> +		 */
> +		do {
> +			object = slab->freelist;
> +			counters = slab->counters;
> +			new.freelist = get_freepointer(s, object);
> +			new.counters = counters;
> +			new.inuse++;
> +		} while (!__slab_update_freelist(s, slab,
> +			object, counters,
> +			new.freelist, new.counters,
> +			"get_partial_node"));
> +
> +		if (!new.freelist)
> +			remove_partial(n, slab);
>  	}
>  	spin_unlock_irqrestore(&n->list_lock, flags);
> -	return partial;
> +	return object;
>  }

[ ... ]


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251024142927.780367-1-clm%40meta.com.
