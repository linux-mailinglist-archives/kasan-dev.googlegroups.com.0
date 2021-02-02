Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64L42AAMGQEH2QIKNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D049930C6E1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 18:03:55 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id le12sf10301650ejb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 09:03:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612285435; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLtjugvIQSCOKblDTRCSeCBoMWlmx56l0isM/b8s8s7eMfHzD+CS46uEj3zrTBsb2w
         r3qbkuTsWhk5+nXI4KV2sSG4398Ej4YMLsg+QZPXdId22xeWDQNAQfC0cK3k3qlzh/YQ
         h88zNTE1tDt/PIhfi2lGhCPXUTqWYql7w+V64Tgs81gHMcLDWV13TdOgtVZ1UjM+szAU
         7X0Cq56EYgTltxb9YFl22UbZLsyWxGUW2N6MTlUIFqAWwmrtIFkf6I3WQXN31O27aMcg
         GZDl0wmyCeR4j0meSSGEYWtv6VzNP93wCUNGgroe1uGu5WgluC7RnxsMjKESUcSYK5rl
         Wpog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1Uf0U1euOHO/kNXLe2KNk0rVBskzQi7pnry/85J2VUk=;
        b=dx+kwJ1A7T/rpptyMF2cC/unR0uYk+zhYyOFwEhnZus+P8ova8UuozNPYoRvIAeF2w
         r0XoRYGY1CdDqsZ9B8un2ZE9+V6/dyfWLPh5KAJv2ec4QLeSCY4z2mO+nKGLdnIl/vm/
         RsyiCFgm3Ki+OVJzqwfxDvdoecSvhCCKE1QryIDfbPZeGCck7cGjHe2frahdByY15k/K
         iXlwQQmKQYf4iYx1ajXng1f+YV6UZ7pihTqz5aegkBR5wKhFfqjgAUD2gFHCcQQ/w8hk
         tb74KbtH5VXE9fM9NZw98meEyFG2qbGD/DTY9/bWZwHC6uk5e/FsSLcms37BeqqoBRvz
         HHzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TzVMfjf+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1Uf0U1euOHO/kNXLe2KNk0rVBskzQi7pnry/85J2VUk=;
        b=Hij2SzDF4erW5RmznrQyGjXCmtNnqJMSN8d5d2k5YjZ+YzxnvYHhhNla6vIkQJJVTI
         zhgJ/h6NKwNlR+IMto78v5+n3sSqA82S/i+dU0WCpss0OkmcJZwV/ijuk6Y2L9J7Y0SK
         xtlM2fJw44aN9+cE4eeFfzQtnQnZV1ZvoKv9rS8qpnUsrrRwD51IDLh9xct+ABWvs6H/
         mGBxJ+Ta6QaBpWF2+JX7HZZTHUYwYDRfSKlgdDubWd2LEN3qbSZQPdRoIeotu7u8pOML
         6iHHog1IEzTL4jdFtUjqbvU/JCrWzIbSN0zBckLnC/tethVmWWZ4P6toTFUXXIvhbBDG
         HI8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Uf0U1euOHO/kNXLe2KNk0rVBskzQi7pnry/85J2VUk=;
        b=XCh9+iwQMwpYA5rL27t4JE/NcrVPBgoIsle0qSQ8lcxFBIBpLDyUxLIVlyll+UT4Vu
         MdPBdxoNgcKfzWilB5snyVhWUq3j/+G2tlqID4M5vDT6T+dgfW3MX2wbHIkeJmttb5Rq
         aMWjMSpiSvZA9tJgMgHk6eEtofBmwCuqLRnvhsC3JgwWqHsPnprLWIi+lJDhnkCqlzF3
         ro/d8IjZ5rVk5j1LHnJccS8sDtGK1MK4iIWLv2BNFKMxHuIA2D9bFNE3SipC+bbABIOf
         YP9/x2Moo3JHgQXC5XWRMhWrjMQMaEkCMR79s2Ci034G4+b/rmhwALthRCpwof7n3RTZ
         XlvA==
X-Gm-Message-State: AOAM531dnn/wPVknV4mNmi/GjZ8K8JPCaN+InCOFgEd2duXr0D1Nx3dw
	pfWssM42I587MdqDdbU8eMI=
X-Google-Smtp-Source: ABdhPJy8psn9ePoVRezkIncFYYdmZR08nMHEk6aLzERmIOq6RoPe5RrLqrEZP2GYJ06y4wRnd6Gh5Q==
X-Received: by 2002:a17:906:1b0d:: with SMTP id o13mr23842530ejg.232.1612285435628;
        Tue, 02 Feb 2021 09:03:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b209:: with SMTP id p9ls927080ejz.4.gmail; Tue, 02
 Feb 2021 09:03:54 -0800 (PST)
X-Received: by 2002:a17:906:7d4f:: with SMTP id l15mr22630622ejp.95.1612285433986;
        Tue, 02 Feb 2021 09:03:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612285433; cv=none;
        d=google.com; s=arc-20160816;
        b=jmGJfSkiwJPGKQMJvm6IuqtHYyJhcwEfE5YGslP5aIFfbD3o7Vp3jeewwVBGKz5JQl
         ARgLAV7SADAZKzgsX0KawMrg3jVvaz4+KTSDkZG4zj8VB2fH96KbpIo5NkVm8p/N5+NT
         IM0RzPVGxeYeMlSk6P6NDVJuM9P+VhNyhFOAMI2PkEuxGofjxK0PdSsiSjb4yW4vOd9G
         EXJmqPB7sLHTpQQOCdkwvwnfBc6yR4wR2PbJhgZ+ho6VCD+Kb8eCLJ3ICnlBkVNYe5lK
         BL1t/qs79gX/MCM7KDByhO3neMyhcOhgGdAKstgqESAtMYRtyl4R4zNb15HJ1kRGJ3ID
         yTWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LlSpQiAeO5UD+cdMKYJ9CnM6vv6XdQSneSZu18Ir1hY=;
        b=ugoaJoUVPqMvuxQtZl5OC4TMecJvuQSEGMV2OrqclOoXkXap8pL5JXyiWm3Ub5g8BV
         KbhZIo3I/meuyDIDFIn6zVB1+88w+/LgJExFYiNGEpA35puhG/A89tAVrC53yip+sTbU
         Xf+jG6ZO3jdmbG1Dfub793OgIhdevT04LjzbMuZIDWs5kGJnExmdGIili+IaZX00zggp
         YGpxF0MoPnAEG1Z24oqkEAM99hxQ0i/OimOYR3TB8UqzsL7ImOh+R8Wyl+bhdVbHaoDe
         RKWHMJnVlfskV6VVi+IBoei0p5ZRGVtpeewSHbfYJ4ug2XjNZYX1dQNTUwe+nVS1tPg7
         BuWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TzVMfjf+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id ce26si561254edb.2.2021.02.02.09.03.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 09:03:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id w4so1866277wmi.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 09:03:53 -0800 (PST)
X-Received: by 2002:a05:600c:4fc2:: with SMTP id o2mr4462198wmq.90.1612285433466;
        Tue, 02 Feb 2021 09:03:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id q63sm4041403wma.43.2021.02.02.09.03.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Feb 2021 09:03:52 -0800 (PST)
Date: Tue, 2 Feb 2021 18:03:46 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 04/12] kasan: clean up setting free info in
 kasan_slab_free
Message-ID: <YBmF8gCRRdRgJw0/@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <e762958db74587308514341a18622ff350a75d8a.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e762958db74587308514341a18622ff350a75d8a.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TzVMfjf+;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> Put kasan_stack_collection_enabled() check and kasan_set_free_info()
> calls next to each other.
> 
> The way this was previously implemented was a minor optimization that
> relied of the the fact that kasan_stack_collection_enabled() is always
> true for generic KASAN. The confusion that this brings outweights saving
> a few instructions.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c | 6 ++----
>  1 file changed, 2 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a7eb553c8e91..086bb77292b6 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -350,13 +350,11 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  
>  	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
>  
> -	if (!kasan_stack_collection_enabled())
> -		return false;
> -
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
>  
> -	kasan_set_free_info(cache, object, tag);
> +	if (kasan_stack_collection_enabled())
> +		kasan_set_free_info(cache, object, tag);
>  
>  	return kasan_quarantine_put(cache, object);
>  }
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBmF8gCRRdRgJw0/%40elver.google.com.
