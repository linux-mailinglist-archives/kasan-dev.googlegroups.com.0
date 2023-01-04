Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBGEH22OQMGQEEEZUKBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 23EE165D4AD
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 14:48:09 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id ay32-20020a05600c1e2000b003d9730391b5sf15614521wmb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 05:48:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672840088; cv=pass;
        d=google.com; s=arc-20160816;
        b=KQOTXyEMUYzPJeCZqrLpHUnuhPalsbJTqfjdRlGYCMKFQXgbEmRE8sDIgL588R0eEw
         5HXeAB5c4ClX0p1mz8yHiQ+lalVdzCFc6X8ZD0c8ZeWH7gpkcFob4w+76DIA88MfQb3U
         XrGiG+TcC50V8ZV8M9mxmwxdFMT77nAGI3Ebpl5S1mimrSOtTW9wIgIHND6hN2rHhRT+
         nNLfYhxzb39l2scZhcqdfzii0Bg6r2wSQsvFV3n6X99VYOWnbx4pJnjGSr3zyrO19nFH
         zB9v7hJYLYiuCRL7h9iZrdmZTxwLmTcnSPvwrPSGqvRr2x7qV4mFkt5doS+DEumieEa5
         jRmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=4PvGwyo3hwuQr+1Ai9N/3VKBkOYU6xdpfSbDH7qixPE=;
        b=p1QZEHo7+Z15ZP6ZyQFlf93TrmrrqrlwL4y/ho04YgGlTA/tm6Lrkk+1KEYZ/8aYom
         UhNMxEC1C8qDMoG7cU+H9sjlwyKglxqdsbJEiTam6Rrbrq2ttgmH9z8RGrlWjpZv565R
         jKrxCGJqJGaNcJLKWFFdQKxmpbCCp8LEfXhGWsftob8BsKv3wIVYyqgl6GSoNRZc29mA
         0h7uSpf0xfRjNvVYGYKNekx7wlbD+o+zTNGC5as2ylAnXbqEf6AcGBj/B8oC8BLtYME/
         bTwmyMQ9P0Jmdqng9xp9KWptPVjpRWe6UIZjhWrJ9EltX0PO+FMUbLQXm6jwomJ0hhxn
         2aaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2B7F5Pj;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4PvGwyo3hwuQr+1Ai9N/3VKBkOYU6xdpfSbDH7qixPE=;
        b=aLMrvMX0L0vYDKovZ+SiS/74F01z31180FzYZW2lOztFn5cBzMKi+w6xw2Gp/NFKCY
         QWma3Q43TACKSPo3JNnKSzRPC02tTmSjRsWE+OUSeJJI83QyX8Yy0DENbKoZHiT7Rvf/
         x66FDOXGajdZl/XHgO9VBV/0v0PkMEjfzU+1qhogVjzJLd7dDEZQvr4EIlZsiWRAx/Ap
         OydwNgqDcfOiGWBVZ0chc1sgDWMUwqizADHUiY2Mbe8wyzvZhHGyDcou6wD0818jpi1Y
         F/IkD7XUVTcp7ACtuCA/zgAXRiskx/YLmYQFxcfhAvBJKxVFfi+/T5M3ehswiHsUUMlh
         fs5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4PvGwyo3hwuQr+1Ai9N/3VKBkOYU6xdpfSbDH7qixPE=;
        b=vMDMBRjeRZnsBDngcrjYpjAXRDyyxBZkVPNVHnPiP7HzxY+80QRLjNoLxCtJh4A1q9
         0JeCryPVEJMjxXFyDfrP6B8MFRcsHJOl94JwEkG/IaGowQtrZx3Tnki9yzLVU/1zNU3g
         T72i8rAdVI/V4JvDOJX5HxXBaLWj1DDxx3CwpG8QTd5TbL/GcnYa7ozhVaMheOK7GkFj
         IoieFzJGaHl0RW8jatuwJpmjZDxgEUtCS2t1S5XLHqzHcW9De674lx/f7lD0Psid5DpS
         IozvSTbw4rnzUaiO++F+HFDZvAKtMfnmKrG+aW+h2POkqko6CSe3VfwE80CXepI+ik/3
         MUuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krT424VL4DakjTrID8n21tdFF/cIcyDFa/89V3eU0HFgDDGfhlp
	/1yAdQ1VNFmrQ6PTmg+CWn4=
X-Google-Smtp-Source: AMrXdXvGjW5UE/0l3NX2ymP71Ku4lhrTFYSrx3cWQjENnZlVbuCq6v+JW1t1v6M1ZJ/OykrJN306XA==
X-Received: by 2002:a05:600c:228a:b0:3c6:f1fa:d677 with SMTP id 10-20020a05600c228a00b003c6f1fad677mr2367146wmf.59.1672840088559;
        Wed, 04 Jan 2023 05:48:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e182:0:b0:298:bd4a:4dd9 with SMTP id az2-20020adfe182000000b00298bd4a4dd9ls294847wrb.1.-pod-prod-gmail;
 Wed, 04 Jan 2023 05:48:07 -0800 (PST)
X-Received: by 2002:a5d:488b:0:b0:242:5ae0:5b41 with SMTP id g11-20020a5d488b000000b002425ae05b41mr30974398wrq.33.1672840087294;
        Wed, 04 Jan 2023 05:48:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672840087; cv=none;
        d=google.com; s=arc-20160816;
        b=CrkxV+I+e4oeneD+6TnsUjyfoD5nhGY6uIS2I0hl/OjQP7M1hMTplCBWyFffG8bfPJ
         E2i5a9jiTwM1iK0NfES8NCEblpp4MsKhEeg4xQd9upjdHC82EyJa/pkAND/mIH6UWG7k
         KYcWT4FM8P0V6iz6teItibWLDlvRg8e5niFWFKnq/QbsOm+FQN/8w2tXssBdtLx5CHak
         zAa6oLen3TJJqbqJhb0hAU9NHUbw28wolQg9A/0c7nuwL4sxbyQBckRTdges8v4XrH3o
         fkRV1eWsabGhTh7XYZamcaEjwG4JqcadjAIIn8JHg0NRYF4xq6uqcM9tY3TV0O+BstkF
         Aobg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=A/xrkCTOG/VuEr/7vz/dj8OhDz1eXgBlHor6iAWeh/U=;
        b=DWiurBPPeps2SsH2r1+2a5tCIIXqi8gKTfYp93HDHikOB4ttiXxunJvbJCqhAoJFPn
         QVzJnjNL78K91xt8qlB8gyGqy+CAB1I+ZrPFvnaU6pHf40URdBo0Zk83bRdbqiPCu6gn
         AG+PIeBE4qNa24OfIJkvfOaa+B9dvxqrwkalwxm2gnTKQNyJUrf0fIYrJm9JXNRb33Ac
         c5FPcUfGkS+i09GstbPBPn7+UFC3PplBOwZho4CXQorL15Z6eHO9wySafLgCWnR6li1M
         JiGrViXtYssdYbZ8A/gnQQKsXhUiECL4Do8UQEDjlfuHkakS27exYkpsc6QaWqUsMxvG
         KuaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2B7F5Pj;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id h13-20020a05600016cd00b0025dd2434f36si1152628wrf.2.2023.01.04.05.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 05:48:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CC3222065F;
	Wed,  4 Jan 2023 13:48:06 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 9C61A1342C;
	Wed,  4 Jan 2023 13:48:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id zriTJZaDtWNvPQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 04 Jan 2023 13:48:06 +0000
Message-ID: <d4f1073f-6bb3-15ad-7ad3-575b914ffe6a@suse.cz>
Date: Wed, 4 Jan 2023 14:48:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [Patch v3 -mm 2/2] mm/kasan: simplify and refine kasan_cache code
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20230104060605.930910-1-feng.tang@intel.com>
 <20230104060605.930910-2-feng.tang@intel.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20230104060605.930910-2-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=w2B7F5Pj;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/4/23 07:06, Feng Tang wrote:
> struct 'kasan_cache' has a member 'is_kmalloc' indicating whether
> its host kmem_cache is a kmalloc cache. With newly introduced
> is_kmalloc_cache() helper, 'is_kmalloc' and its related function can
> be replaced and removed.
> 
> Also 'kasan_cache' is only needed by KASAN generic mode, and not by
> SW/HW tag modes, so refine its protection macro accordingly, suggested
> by Andrey Konoval.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
> Changlog:
> 
>   Since v2:
>   * Rebase latest -mm tree, fix a conflict with kasan changes

As it doesn't apply to 6.2-rc2, I assume (as with v2) the mm tree will be a
better route for both patches than slab. Thanks.

>   * Collect Reviewed-by tag
> 
>   Since v1
>   * Use CONFIG_KASAN_GENERIC instead of CONFIG_KASAN for 'kasan_cache',
>     as suggested by Andrey Konovalov
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4f1073f-6bb3-15ad-7ad3-575b914ffe6a%40suse.cz.
