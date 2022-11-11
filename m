Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBYUJXCNQMGQEP73CUGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id ED40B62550B
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 09:16:34 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id v188-20020a1cacc5000000b003cf76c4ae66sf4066529wme.7
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 00:16:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668154594; cv=pass;
        d=google.com; s=arc-20160816;
        b=rjTnfxTQ+YP57Meg2X642t41NSmbqzyIsuGeGBAuZ03QjogNxGKywu1irG1phALyfS
         5RvxEkJnpl1lAC3/kmD3gN3LS86/WibZNcfM0dIJ4DVJY1sSDxFzbTfz7uybF7z/yPum
         enJeRiY7TWGpmSiAzDag5H9L9RZi7yiV9eDWn1G1pqbL/b5NrYYl2KTBeYitQu8ofl3F
         KA3PrhEHC3NTrPBCpFLDultX28gfyWO7DA/1e3D25XK7zd6BgUbAGdUBqlsdAMYfKIkA
         GPd/ImQU2WsxNaVJ7YCoKwimc/GdzyaZphq0doH64qvYEo7zKC+oFgEpSZ/60n6SF/pB
         z9OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xm5vUXv8XC0hrYIRGd+vfd28ynV/SEcUviwPfP2lzsk=;
        b=N82TatFIxVbZKO+waOUlY89iDKpzJNuT7dTN+EHMqYix0CHc2Qa2wj8IuEiAUy3/uQ
         y/LRE+ZwtwUeFZdDkABp0rnZwspfom61ywNZ/0WcHSSAqV5b2n0Y/Ks7bawIp6yoIbLD
         Tha/5EBQYmH25zz0+o11MnpAN8iYIKW4qKB62kEqSK/WRdf2N/S9sqEzgeDkDhIoy+Qv
         MLZjXJ4U++PnNlQWBXzIuPcnsLCUbOB2vtYC2mkvldJmUo6ChVotS35FCKWjkqQRW5Co
         ZmaGB4mcn6zOtU1B+42Sc9yajK3eRLUHVPZh+vwBtEwBg2/fVfp+6HuHqw8/bXLXeQXj
         2bfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fIwWWpAI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xm5vUXv8XC0hrYIRGd+vfd28ynV/SEcUviwPfP2lzsk=;
        b=ncTzRt/41MkYdRcp1Kcpy98QuKypRvxmHBEN2Yh49f1oDFv44fIXNUmj6XRzvERyM5
         bQTsAr1b2rg+xzBw4B9Glrqz5GIqdBPjM6itgsYWGNTliZC4VcPVAWqmRyk/S1P3rQlu
         G9fBK/eTAdu+tCK/BmzyZAs5r+OvzsFOhJem6XzGGiKZjm4iLkbgpyz57kCqMTK6oKEN
         w7EPV0N+ysRlGIUZIP2z1FM2KBYECypO3ddYVhRxOY1/CsIHw8OXDZfFciPKjA9yhvoW
         CF1ZT0BFYiJfLfqeIeRxhW9hfZ2OXXv+iQYKVZrb2Tob2PkR1A9jk1736UGM+M/A4kLB
         BFwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xm5vUXv8XC0hrYIRGd+vfd28ynV/SEcUviwPfP2lzsk=;
        b=Hk/dBOGFb4Zwidrzx1vYvkl8EvtKtP6ovGP6Dc00cAgmnINXhLVjNEuqZxEAxtGmvB
         RHaEWpgtvrVkuSR8bhDZIC/RVcZduuyxAyGLXL5A7bEbyYBguae3mA7lGFqr0MQcSQDJ
         YJFWJUn92MpdE08Vmrx5noGg4H+F/LznzDBXOV6hkQyt6M6NdmJnz1F4FEOiPb968mxf
         BXA17gUR2ONyLP6r861CrINsPaDzeK2yxy4NOAUiRj0DKzfD3F8yQy16VFRjK1d1OWTu
         sh1HJPSi01v4BywyGUgsJPKI172IyJ2uATarAMsKv44Xj3TmWvFZ8BKm/Q16ug8ywc2a
         o9tQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plgY8ReJKEEIPstvhCN2Ax9yu2HCiVXLbtq3JviM8txaFjHENbk
	s0Sz2ozwdFw/xW2InO5E7I0=
X-Google-Smtp-Source: AA0mqf5n2LDDop4c0UtEEQuy45KxVTfPlkXNL2olqDBVoJGAbJE3uLWjPB62aplZM4l3VTL6GSTVFA==
X-Received: by 2002:a05:6000:1b09:b0:22e:5063:8f20 with SMTP id f9-20020a0560001b0900b0022e50638f20mr524325wrz.151.1668154594754;
        Fri, 11 Nov 2022 00:16:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0f:b0:3cf:72dc:df8 with SMTP id
 l15-20020a05600c1d0f00b003cf72dc0df8ls3718925wms.0.-pod-canary-gmail; Fri, 11
 Nov 2022 00:16:33 -0800 (PST)
X-Received: by 2002:a05:600c:4a97:b0:3cf:9d20:55d3 with SMTP id b23-20020a05600c4a9700b003cf9d2055d3mr452131wmp.58.1668154593539;
        Fri, 11 Nov 2022 00:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668154593; cv=none;
        d=google.com; s=arc-20160816;
        b=aDRWtLtBkNyvl15Sv8/V0nK+cEQH9OxtHCgp1xOjks5CDwo5W+Xv+b4cQit+XnrdXI
         Dq9oRU3PiXfYBDVFLPQPu779ThOL9FUTXEKJC1XLsugx+GEYotAEoLEaCszzoWPa/Ym8
         +hw9CMnHq2GuQghjgfYFG4iHbNI8tVKmhK1WGxnJSojckLY8Lss60jLxYOPG4XtbI/nb
         6U0/XVuMoxKHt2l1o3613x+oX3mFk52aSN9vnNcbA0knxcsRDs9RzRLx4noqDXeq3EhS
         kS2IT9zikbX4HFBQKp0477N0uUoL8jT3hp8JRRC4o/yG+hglgO1tl/acxT+aArbN8QCs
         E9CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=K3QYJ2EXLu+u4WaeAKt86AUgaddU0ZJc+TTeHOeCaKA=;
        b=PA38ph4kVvyPGVi+B4mV1/2myPkxqa6titBrKWsLlARRvVmrZio+teIhCflHPel69A
         n+aqb1UsXaSFuKPEdbVsdK4HWQ+p9oVslOxPQzL/V3vpynvbKM4NysfVnpRIJHEfL8u9
         80jAIiCxbh83jVGdQupK2ckCSQw85qPwT3/cOlXofqYF18M6nnDpybjSq413f4LS0sZd
         HVFldQZ2OarFQ2mkIIs2/x+ScQNoheT3w4jZFb0oKBwNLpKhk4T+DLkGifiZS7iaC3dU
         92HOqwlml44GJlgvmLyfOsRanMjWv8LOIJB5oRsAO+PQV1LUa4nNECOdtb7n/eoH29bZ
         xH+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fIwWWpAI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c3-20020a7bc843000000b003cf1536d24dsi90763wml.0.2022.11.11.00.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Nov 2022 00:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3E5342206E;
	Fri, 11 Nov 2022 08:16:33 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0EC6C13357;
	Fri, 11 Nov 2022 08:16:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id rJP3AuEEbmOuOQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 11 Nov 2022 08:16:33 +0000
Message-ID: <f9da0749-c109-1251-8489-de3cfb50ab24@suse.cz>
Date: Fri, 11 Nov 2022 09:16:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH v7 0/3] mm/slub: extend redzone check for kmalloc objects
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20221021032405.1825078-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221021032405.1825078-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=fIwWWpAI;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/21/22 05:24, Feng Tang wrote:
> kmalloc's API family is critical for mm, and one of its nature is that
> it will round up the request size to a fixed one (mostly power of 2).
> When user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> could be allocated, so there is an extra space than what is originally
> requested.
> 
> This patchset tries to extend the redzone sanity check to the extra
> kmalloced buffer than requested, to better detect un-legitimate access
> to it. (dependson SLAB_STORE_USER & SLAB_RED_ZONE)
> 
> The redzone part has been tested with code below:
> 
> 	for (shift = 3; shift <= 12; shift++) {
> 		size = 1 << shift;
> 		buf = kmalloc(size + 4, GFP_KERNEL);
> 		/* We have 96, 196 kmalloc size, which is not power of 2 */
> 		if (size == 64 || size == 128)
> 			oob_size = 16;
> 		else
> 			oob_size = size - 4;
> 		memset(buf + size + 4, 0xee, oob_size);
> 		kfree(buf);
> 	}

Sounds like a new slub_kunit test would be useful? :) doesn't need to be
that exhaustive wrt all sizes, we could just pick one and check that a write
beyond requested kmalloc size is detected?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f9da0749-c109-1251-8489-de3cfb50ab24%40suse.cz.
