Return-Path: <kasan-dev+bncBAABBSVMXDFQMGQEL6PKGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id EBE20D3A6E6
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 12:32:27 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-38316f5d922sf19514021fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 03:32:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768822347; cv=pass;
        d=google.com; s=arc-20240605;
        b=OgR3XmVs4v4LRCVPFNg7n9G+RMoig+QZRdSDAeMiVglUmDfuxmlna0Uh6yLpD/CLRw
         HsgiiCfh4spOvnpYihBCBQFqh3pb0MDJPH1+dlF5nxWYNOF44+JV0BH2jAkJeFJapjDH
         r4/3mhrg6v7clOasjXAHtTVSSbC+dLL8DCxJBZHOpR3Lf/I79rxr0bOGO55bkoGgbtLZ
         nKTjGmgPf+aRlFLTMmzZd+UoHRX0zj5882O/pL2obwfGHgxCdfpw0UEzbywaY1lhRGuO
         yYIX6EtpuxlnAHYTEH2Rs5siMzAx49tuiOTcYH32vKibCNXu18eOxRSpv6mW0hmUTG2P
         Q0aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xrfjTPfHo5dIoqcCskuVVbdxAfjbQf6auwk44E9wgXA=;
        fh=jG/Xrbk6kYzaHx5cxB+wbw8qLkNxGeitpihHxKG3Nz8=;
        b=gl1CIrCeNbisNwpGpqs9dCnPZ/CRXdk1fDDlpD1T7Rk8AmdCXV5FZpKJsOJcGCgk59
         pSoSV67rGxs7ywjkwsRTu8cs7fN6iyjhm+JixV3KPqem4ZNdk8uUaeJ4z1AlZ75w7wcW
         lVUWmh5dBqbPuV8zytTyIIii/PleHTG8/llHsQlE6XWOrIvHpRbF2d5fGbtgiH/UpKpF
         WdcZEUd12LTGWowHmwKcQUzbUffEI1MEDSHMj6bgcg9ZxTCHmSjiy2FuJ5jQAvcyqkw/
         c+6tHUX4NyudTjLaJzbb83swX3C/VEA7NY2upHEyr43Fz0uTa52qu+/XhTeb+4bz6w0+
         YWeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H9fF1520;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768822347; x=1769427147; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xrfjTPfHo5dIoqcCskuVVbdxAfjbQf6auwk44E9wgXA=;
        b=chVIUvBpPDBoJ/hEZvUa2bBLBOCaFukgm4P0iigSP2eXu9smz7kx5A+W2uQf9+Rl2J
         VfRw4Ntr1bv0YB8aPg0AluKJ3uxUQU/khxS1it+cpvY9r0Hhf+qNduDjyUCRzckOJ0w/
         L+Lq9kinpJ89ArPE+L05ImAmLcDaTIYUJZVOmTEYknz8zpt4DFYx8Ph+8qWWDc57WhSX
         iqWI/XsqkflxGirPwCO89jTpV3HWm+OHvbsoCnrmA9tP69eYrg/+QesnSNi6wBPyqTRE
         e4WCJuOujrV9hF8U7JzXEXlP+UKqcRcmKKF5lYWbn08QHYi+eIgpJS9QZllz6KICdauI
         Gouw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768822347; x=1769427147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xrfjTPfHo5dIoqcCskuVVbdxAfjbQf6auwk44E9wgXA=;
        b=Bn0Mfa9lSyCh9Z2qpsPqfUDC3+V9ApBppkJpmI7yXKz4jZClunZTQXjaJtNMRrDv7h
         IJmzeXgIzUTmTW09QuS9NcvzyWOWaKfjGxTX8joaDmWkFO5fLbsRfQiAZCLuO9rrzjqN
         4TcHs4h5Zu2M2PEprReictwyXLrkRzddETDlnaNtAClb1eQapy//Vgy+9BLxw/b0FmSq
         kPaSvAYmEoaj0s9xaUqaAqtRQRUlkRNRQaHfbs+JxrtuyLLh6lVpxoCLEl+MpnxRURg6
         vw9xp8SPoUtjlN8UUj2cnh00XzDUqLMZ9XVmst5p/mRoh7s/T4gTQpHvDLw49PaufQWu
         CVnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/wQYaXEIjbrtsuFqKMiNRLgwsbnBGxWgIpIzQ6yOkYvneLkq/+E2Bvf6VaaVwEpwUnefImA==@lfdr.de
X-Gm-Message-State: AOJu0Yxg7X1NQCEmF/RV+/ObCCobsmhkyBqDjCGujm2LrYN1XZCpYLFW
	qLeMhPVdcln2a6/k0lBwzQAhGe8JxfV6bFH3zirWFns1tdLKiIcCKoNU
X-Received: by 2002:a05:651c:19a2:b0:383:f7:1064 with SMTP id 38308e7fff4ca-383841d106bmr30152331fa.18.1768822346799;
        Mon, 19 Jan 2026 03:32:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EBL5mLkce5cBn79gQF48S9kt3F3dXf4Eqzcuxq11gaiw=="
Received: by 2002:a2e:6e0c:0:b0:383:1a5f:713e with SMTP id 38308e7fff4ca-3836ee0147els2665061fa.0.-pod-prod-09-eu;
 Mon, 19 Jan 2026 03:32:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXv+eQ3IRoy68HO1pJ5ZQ2xWA/XwqOxVA74Ritj1MJEPFgD3iYLjJFw55wx4F4bCLU90BMJHsK3lCI=@googlegroups.com
X-Received: by 2002:a2e:a98b:0:b0:37a:7d5e:db9e with SMTP id 38308e7fff4ca-3838416b953mr37849581fa.8.1768822344517;
        Mon, 19 Jan 2026 03:32:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768822344; cv=none;
        d=google.com; s=arc-20240605;
        b=Qjnv7l5NakqO+3hSSG1VenEqrRgmbrUwcCRAYMS/ZXGnKuETt0QCkikO7gH/UENlf3
         5DcAuoqmWDEW8QUs1mRTbF+38fAuSCbfMVm2MSHnS5D9fNLoK8/EWpr+iV6dk/q+ZSdA
         vKldpDuqfUBCnA4FNyGeTwzG6NNKToOclJCkezla91U+1cX0y/QTxV/G+PfVB5jWlPnI
         D67fuC6SMDPmWMtprS55LSVuQBBlSCFQORsby7lR0rTBcMlE3gasnbf6SQwdNSU4T+dr
         QhCytNe9iZ83/TtfkOACk2xONzjbEN/pgygHKjZJLF8grCbhk48uoisyZdLI/5Ch8Ibc
         DpGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=789MzptrG4PzrEbzbBX5NhrBO/HqtHp6WbidgwoRfUk=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=AgMOT6oJWELWO5921CxXy3P/W/qfcsPgUSpYOiOpZ0RFfW9rb9xogEroA2CNvQ02jk
         FAPL8gc8jdCmvLNYbkgWNXE3Z9h/kl0CbrWk++zDqgigdakoDEEt44PwNs07zmagf/+1
         czyNbfT+ZFy9NmTH8r21dYz7qi2XoXtRfELogsl7yZNXoDkpUcdwFnEKeLIdw+XuJRQm
         qOhOd7C6W76pBn+r1NNne8YeOCojxC5zb+FH/j3ukdKfbIRErsJRE83HwgOSkZ2E1RVV
         tF2aXo+bzyHYU+9v94LkPOaIzNPb+AKqmd/GWGFoML7E0gu48sWgnCYIY2T7C1o9fo6O
         mETg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H9fF1520;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [2001:41d0:203:375::ab])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si1998261fa.1.2026.01.19.03.32.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 03:32:24 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ab as permitted sender) client-ip=2001:41d0:203:375::ab;
Date: Mon, 19 Jan 2026 19:32:02 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
Message-ID: <7rzlxxqawgasthkhlk2fccync42blr3mehtfbylcsihy7kr5m5@m2bzma4qifo7>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=H9fF1520;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ab as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Jan 16, 2026 at 03:40:26PM +0100, Vlastimil Babka wrote:
> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed, using a new
> cache_has_sheaves() helper.
> 
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
> 
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we use cache_has_sheaves() to
> recognize that the cache doesn't (yet) have real sheaves, and fall back.
> Thus sharing the single bootstrap sheaf like this for multiple caches
> and cpus is safe.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++--------------------
>  1 file changed, 81 insertions(+), 38 deletions(-)
> 

Nit: would it make sense to also update "if (s->cpu_sheaves)" to
cache_has_sheaves() in kvfree_rcu_barrier_on_cache(), for consistency?

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7rzlxxqawgasthkhlk2fccync42blr3mehtfbylcsihy7kr5m5%40m2bzma4qifo7.
