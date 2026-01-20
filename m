Return-Path: <kasan-dev+bncBAABBXG7XXFQMGQEPJJRSLI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KCQHJTCpb2kZEwAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBXG7XXFQMGQEPJJRSLI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:11:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D2674724D
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:11:28 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-b8701569041sf538036466b.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:11:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768925487; cv=pass;
        d=google.com; s=arc-20240605;
        b=XWCBMdj04DP1Sq8Zs9Oj/Mt0zg/9QTkcVSc8r8VexmUpqcN06jOPVu7ROm2o8nG2pQ
         KBanmAgRVoJ9uEj/PZxojVoQr/yvOaI1hOTLig4RM2YkkxOqq+4pLYP6rOK1w+Z0mhuJ
         ksWVJ03QFuW2CEhMMp4KudtTcJMa3hhNPFRrO6epPbRYasr5XS4gPqP+sAtyFWEsZ8DQ
         O+5l98RPMdZv4iHn4lEG5rQG1AsNXgmhRMXrnfX/kWp9kpQ1MdgoFpBrPAhBg5+IPoIw
         6V8fW56+x9oI5NETl7uihQD2gRVnt/8z7vbwBD+M3nDxoujYZtWjypwTuhDN2v2LIy6J
         lAgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kWyG7AN4mbJxAZ2OuTY66g9P05hreWOXW5QwKLScPGE=;
        fh=hJ+tDGRURCRmHzHL54m+cZSfmi5qcp7b6ZFwys6A/yM=;
        b=jblzDyZzzNdM715ir/VEVK9wHfdhmMKU2THQRnzt/Clly0js6BswhQPxIZetw6TGXa
         Mn3CYBc1kZqHAx4DuwkrM/a1/qie0bj2wqhYwdY9YIKZ6fszfUOqHAvw8RrALWwh16rw
         5BUqNP9UvHHC4axPDQ7piOtuAExRTZhDPSkDAsbKY6R4HmNtgIzNDwdWrooXmLoPd1dO
         RNkxWlzpYtXdCijB5Wp/CSL98L12AHddEi8z5utsRCKInaDIOqq80n/IAUGvHgMe8fwi
         zha6T4KAHN7I6Gq6BDeNfoh0Kn9agFeFbA9xf1fQsmt1t64iHmLA7lbojDNKpLsVc6pt
         RlLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="B3tfj/CD";
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768925487; x=1769530287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kWyG7AN4mbJxAZ2OuTY66g9P05hreWOXW5QwKLScPGE=;
        b=ls/pK8EilXnD7PFvvt2DtB3onuJyKovB7GlBKlCt4KjHwT1cRq+OAUzjaheKO0+f5P
         FUS6XxpMhx0j7a0yTfAd7I0fl45a8VlpjJ6qilP9Z2xu787TnnmR6twHy3uWXFT5Sdcu
         v6JKwOTCXeJq0IgOTn77wVgAV+b0+RIXj/upzPxA+OM7ZHs8gvvNwuQgKo4594VJ4jNl
         /xUTUu0ijh8Gwi+1N8cc2J+6pp/sKy44N9mNSBgN9YgwK9fs1vUXm+GkaI9LZ0vQOHhe
         bxD0HLbcbEpLbNL1uqU95Gnudg/NeFyh4Mof032zzuISlXuj54owVI6wQuZzfQhd4E70
         lmdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768925487; x=1769530287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kWyG7AN4mbJxAZ2OuTY66g9P05hreWOXW5QwKLScPGE=;
        b=TRWZl3JEh4uTi6VE4gVwF5dVKD2Tko9graYR9HYwpEyic7uDZX+S/R+mKt/AHA5Or8
         dftNK+vD3RNR3/wfkGvv4LzkLzk6yR5piOtzET8QVjBamhwqgIUm0ws13dW3R7t/Y9Bx
         bjH/a6yN0vx77bjbSt03rgsl5TIC6YgGljCeMhJHeLhIYQ45DooH55J/c0/uHlLFinYs
         MBRhDGpffqjusS9Er3l5PnoeNk+b0ztNTlYAZ3BG8wo5f00qw20gPOCBT/L9qwx4tj1k
         QkBe9HjVo5A0j1RqY0t9zAbLpQb1w7pMeHB/wvkxiRzRlqpkQGU4eAoW07J/+IhNce7y
         jBdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwxZqy8JVIW3Ey5/2qDYTsZYqxr9oy0evdHma7qecdeYof3kaUCUPOcUCeBY+xitQ22WWtxw==@lfdr.de
X-Gm-Message-State: AOJu0YxFMGuDLRwXtjBqDblpLbHzWjvuxll7gHRRGMv6YOmvp9M9+/nc
	yL5c1AF1U9HXiAetY5ce1TdGGCehwYrquOEVNiG6SUj7nImmZZig2/L6
X-Received: by 2002:a05:600c:3107:b0:477:561f:6fc8 with SMTP id 5b1f17b1804b1-4801eab9e76mr157921175e9.5.1768910813127;
        Tue, 20 Jan 2026 04:06:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E8D/LoIQK65voPFad3/5KUgQMhaH5P1pvJObIdy1W8Qw=="
Received: by 2002:a05:600c:35ce:b0:477:a293:e143 with SMTP id
 5b1f17b1804b1-4801d787170ls26882435e9.1.-pod-prod-06-eu; Tue, 20 Jan 2026
 04:06:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUtsU0QeZIs0ySO9cvh5+mAhlqjELA99hZyiAXF/dU1uKu04Ne84IpMG6303erKuusK+yBiQoHLeR0=@googlegroups.com
X-Received: by 2002:a05:600c:548a:b0:475:dd8d:2f52 with SMTP id 5b1f17b1804b1-4801eb12369mr174760655e9.32.1768910811479;
        Tue, 20 Jan 2026 04:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768910811; cv=none;
        d=google.com; s=arc-20240605;
        b=fY+G0Y+DluCLPHSK1lEbHIubDBysXQ1FNqAgqX0JpW8/Baiw1PZa6IZQ5fyymk915o
         i/pXuqLWWOCLc9N5RiCX3zdRPKEsTqA49XE7YwFlc8+1ivhbZCJNOuPDKY+XEpKnyvqT
         aNsrmaHnk8CjiVULuQtqxyF+uiTJ1YCJS3RkJ12VF4Imai8w6SYqUZUS5ZTXuBgmeaKE
         tCutlfbVzCpE9JLS541Lnn91F9D2FCf2MEVxs+H9BD/8kH5tmNsVNrA4BUL9JALi5SeH
         hsJDczw3zqAU++TU3bFery5zvORRmrjjGZU0EnSDMz9SU6hfS+PETAPAqsfea0RbqvU7
         R8Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ESCIkjisjdBoNxNmZSiugnc2ar1AP8Qe4a9WPcWHEQg=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=TWQhmdZ+9MC3DBGR7bIoKCg8LIk0EckosYEGPaO63ouyVb3Gbd4Qx9yn+AjpO5J7TB
         LUWDF1c1WIskEqWLdTtW60BM6hz68WzBCHavyi30rHoisM3qd/cMmirNMA2NaoJO1qXm
         zGCB0pEgA7sKRO4shrApbrnFgtMT/ZuzaX1W6qE5coiYqOP1BU2Q2npcE6LD4C5hTfsv
         85PxI0vsH0NIeU7T8HxjUk/EN1OoqtoiMGMENWh6G7PI6Rj/i+Rk7T5WYGNafhO2ShKw
         NpIqjk2g4n7+MeeLanUm7jecJBHGKeNzUvpLG6+JiANDWUIkZTKZF/b01MDPmNg2aipu
         1a1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="B3tfj/CD";
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-48027439b06si630115e9.3.2026.01.20.04.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 04:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
Date: Tue, 20 Jan 2026 20:06:38 +0800
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
Subject: Re: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
Message-ID: <2tvnelafuozzzfyvmxvflqmx2sepgy7ottnw4n2trkh33rrk6b@oewlapq3smvg>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="B3tfj/CD";       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.171 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBXG7XXFQMGQEPJJRSLI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,suse.cz:email]
X-Rspamd-Queue-Id: 2D2674724D
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 03:40:34PM +0100, Vlastimil Babka wrote:
> The kmalloc_nolock() implementation has several complications and
> restrictions due to SLUB's cpu slab locking, lockless fastpath and
> PREEMPT_RT differences. With cpu slab usage removed, we can simplify
> things:
> 
> - relax the PREEMPT_RT context checks as they were before commit
>   a4ae75d1b6a2 ("slab: fix kmalloc_nolock() context check for
>   PREEMPT_RT") and also reference the explanation comment in the page
>   allocator
> 
> - the local_lock_cpu_slab() macros became unused, remove them
> 
> - we no longer need to set up lockdep classes on PREEMPT_RT
> 
> - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
>   since there's no lockless cpu freelist manipulation anymore
> 
> - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
>   unconditionally. It can also no longer return EBUSY. But trylock
>   failures can still happen so retry with the larger bucket if the
>   allocation fails for any reason.
> 
> Note that we still need __CMPXCHG_DOUBLE, because while it was removed
> we don't use cmpxchg16b on cpu freelist anymore, we still use it on
> slab freelist, and the alternative is slab_lock() which can be
> interrupted by a nmi. Clarify the comment to mention it specifically.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h |   1 -
>  mm/slub.c | 144 +++++++++++++-------------------------------------------------
>  2 files changed, 29 insertions(+), 116 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2tvnelafuozzzfyvmxvflqmx2sepgy7ottnw4n2trkh33rrk6b%40oewlapq3smvg.
