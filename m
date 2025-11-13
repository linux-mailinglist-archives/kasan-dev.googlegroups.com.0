Return-Path: <kasan-dev+bncBAABBGM727EAMGQEXSQ2AQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D2E25C576CA
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 13:31:22 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88041f9e686sf8861776d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 04:31:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763037081; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvs46GR39B6jeYOGe+1WkJFhflg3KlPehqW0VV+bu6b/mHwAVhVHHgs9CWBkrKwaPC
         0KMV4dPLazIzqpovYPJT4A/jh02SzgsDA5MmnmbDNn0MctNXLX3LjrBjOYxeu6uS/mU2
         aDotiYCty4/y48z5z6tCJ6Ao6JF7UxM8O9vmDS1YwqaoUQXy/80dKSUgGJpOYOSXODat
         GIxdzv4DtdLMPINzZIFNhIH6RMk86CBkBRpS4Wfjl4y86IkHePyTnI+JF8ocVWOJAZpP
         19spmVbQpAknY9gDQFEEJurwfsDlxkyPYONjoIxOhCjyqImBVthXf998Zbp4/8pnDpy+
         GINg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=dAoUnkcaxSa0AxyCj9WLPHJUR9GhIwu7rUBAOQ5ovDY=;
        fh=ZyzGTgScb2s2nn+1fCHh7SHiX9A3idgecHF5IA2UGCA=;
        b=h2Ke8LaVEKmw7Qt0GT9RT0P8RvoTeyAD9lzoE0NBDrwoRqO6d+/9qLSSMqUidxMRoF
         UeHtBD42/osL7gJKkmEZ7HMTntnubncjpIUUBHotx+8E9TKx/egbJDIyr+OQ3Y82wug/
         kLGc7Tv8WllvevX4eR0CkRsAhoysy5qkmOmLErV5BNtb/a9ecMhp24XuINkuEXLpW1YW
         2yhDGs66mu2N+D6KyQAPs+43zSuxRKzbYVIAOaRzLCu0/XRUeXjCKbsYZoWAG2exbLSO
         +4hB8Z99xobyoZr1IUTIYVqGsX7Yw6tP/aeMGfFAUiaN5s6F7egZdPRr2XSNnOijM5mY
         fhPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WJvLmW1j;
       spf=pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763037081; x=1763641881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dAoUnkcaxSa0AxyCj9WLPHJUR9GhIwu7rUBAOQ5ovDY=;
        b=P0ooAYwBx2p+7AP2qB0ufcMavx2ZRrWwgLBm2/ktqHAUfsImfRsHN7UI4ACvp5oMLL
         wNX/ipGgAUccMBCwtCUAAdLoS3hdOxKnCjWrcHpc+qQdvPD7koEfLmbdpMQskXeBORPH
         Yx0/AlPTkIhtirrJb3X1jPzjnC306iqH6WbCaJd4B2JNGtXOkRebyz6G1qXrC6OjD54h
         zAAM+bFwTTXHdr7f2/ZiOfqUvNURNWIu7d074g2ClGbGYd585ga42N3V2JDnE7EMcoXx
         jl5rZN9eowKR2P8Q9b0A2AL2oQwnfFwKAgqXUZ+vjgvsogzoj6g1tZNFs6tl2PsI7a2M
         fvIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763037081; x=1763641881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dAoUnkcaxSa0AxyCj9WLPHJUR9GhIwu7rUBAOQ5ovDY=;
        b=W1Ah9jPSOC1nqH1Qm0MlM7vE5/kwEc85c5kM+EKSaTdJXliYrStZIsjL0iu1Tn6XLy
         GJKlcUPBv5AStDKUBOUYCOuzGDvfHgrJ0VReJYzDQLXeOcXoemWGd+AZhrjiY2VuIQjs
         wa9YbrcMVbFXyPZTLfOf59SXvKPi0LJ6p+lsS8XFIThemLom452MoMVDidcT40CFgq0B
         fuHkl0KyjpIxkX1usb+hqHuRFACZfkrRnp6iunB94Q7mUaTgQx0T20cAc90BmZlmnA3C
         QbTr1BFLgEDSUtMUEkgj337WtTr5d/B27sF4YNIRTqxygLHZkwbKyhCjqMQivS1vH0L/
         m2FQ==
X-Forwarded-Encrypted: i=2; AJvYcCUbuP52mAFMzuN9xFpMjHTKj5tcpw13SFBkfiB5zRQZnEOtshxewRTIv0j+5RmIxyHVCmWuMw==@lfdr.de
X-Gm-Message-State: AOJu0Yzve/sJSiUJvVQjve5NPDXq4VG/HvGnTgHpug7i4e5uAHa802RC
	4W9wHDyo/oP20dqho8m2W6fLFSKzgdRumridug50nP/rnoK4w8BMgni0
X-Google-Smtp-Source: AGHT+IEL8+sNx8RRKjBA4eck1fXjcHCW9C8BQJs2pVQ5+vmkLmuKb6j6vfUJYMYA56E4fOtLUq9ERw==
X-Received: by 2002:a05:6214:2629:b0:880:523c:a57e with SMTP id 6a1803df08f44-882718cf892mr91604596d6.10.1763037081321;
        Thu, 13 Nov 2025 04:31:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZUpR+8dVgnW1K9xOrtO7puNEfH/27NpZ3iFJ8uJtlixQ=="
Received: by 2002:a05:6214:76a:b0:880:30f4:d339 with SMTP id
 6a1803df08f44-88281b70787ls20682716d6.2.-pod-prod-09-us; Thu, 13 Nov 2025
 04:31:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXE574cwcAisUaWLzXpIbMRvxST3eJbbQhmMA/KpX1da0oaxtAvG/dG9ot+SgQ56wvSnWNARWVg3EQ=@googlegroups.com
X-Received: by 2002:a05:6214:cc4:b0:87d:e2b:cdf7 with SMTP id 6a1803df08f44-88271a4de66mr81799976d6.66.1763037074887;
        Thu, 13 Nov 2025 04:31:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763037074; cv=none;
        d=google.com; s=arc-20240605;
        b=k+v19cYSrC+oDCTXX5vJUYRALbL3wNz5RT+FzMfzd6G5M7qDgYr7/XqhStcXauOf4f
         Iij22CrFrpSMEz5MEL5CIuDgH/LiQigA7yv/YuKBboa8YFlOyyO6iaVVPQPCav/BFs8z
         YR6PP3/WHnTu5WPbe16khNZ7TgSa4/aIHfiIrLMquHs9c76MNEY2pO9dG2AcXX+Y44ph
         hSp6l4rm6H9uapd4LK+GkoPdIwRXDOhy67SBMl7DaYkQDMQkCa1kfS/XQrT/UDTkKEAA
         IwY9fNuH65F13zJ6q5rkdnysBmgFV2o5AaJQltYVZZ/4YGzI3V8fSdiAYb4b25vOGNRd
         6knQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/ZT7sHS+wdUuxV11KqsG/QCLXZmK1oi43WOee9hVSDs=;
        fh=E8avjazBNBVbHNAt115ePy6Mx1+I26fh27H9HxgJlcM=;
        b=FbKXstPunfmu32cOsjdWGXHiHsAnUo9luXoQJ1wHQaHB+PyqgAj3oISVs3gHm/Y6U1
         4J4kcGbfzJxhKx+8NgcWmYys148InGW2jHhYuLpymO2yvEhydVOBMybVFizsioX0etdu
         daJ/7lYV8ob0OGKEIDKMh2cjqQmbhqhdnw7ih9KMaV3aWe8RUMITYLVs5rjaQdFFCLg2
         4AikeMeiqrHsJeI0CrO9k7NCya+BBIjstZhMuvYuKBXNPDgljYPBtajq8CVPYEybGXes
         gBKr03j0j7Olu3WJlf7aGglhFoFPvyHaliCv0Ys0nXFyYIdD/fIMqeBHn96pbs3fEl8o
         Ng1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WJvLmW1j;
       spf=pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8828614736asi975556d6.0.2025.11.13.04.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Nov 2025 04:31:14 -0800 (PST)
Received-SPF: pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 08CB84090C;
	Thu, 13 Nov 2025 12:31:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5EFB6C4CEFB;
	Thu, 13 Nov 2025 12:31:11 +0000 (UTC)
Message-ID: <8c4fdf87-97b9-43e5-8fa8-3bbc9bbe4953@kernel.org>
Date: Thu, 13 Nov 2025 13:31:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 01/16] slab: Reimplement page_slab()
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>,
 Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>
Cc: Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 linux-mm@kvack.org, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
References: <20251113000932.1589073-1-willy@infradead.org>
 <20251113000932.1589073-2-willy@infradead.org>
From: "'David Hildenbrand (Red Hat)' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <20251113000932.1589073-2-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WJvLmW1j;       spf=pass
 (google.com: domain of david@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=david@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "David Hildenbrand (Red Hat)" <david@kernel.org>
Reply-To: "David Hildenbrand (Red Hat)" <david@kernel.org>
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

On 13.11.25 01:09, Matthew Wilcox (Oracle) wrote:
> In order to separate slabs from folios, we need to convert from any page
> in a slab to the slab directly without going through a page to folio
> conversion first.
> 
> Up to this point, page_slab() has followed the example of other memdesc
> converters (page_folio(), page_ptdesc() etc) and just cast the pointer
> to the requested type, regardless of whether the pointer is actually a
> pointer to the correct type or not.
> 
> That changes with this commit; we check that the page actually belongs
> to a slab and return NULL if it does not.  Other memdesc converters will
> adopt this convention in future.
> 
> kfence was the only user of page_slab(), so adjust it to the new way
> of working.  It will need to be touched again when we separate slab
> from page.
> 
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: kasan-dev@googlegroups.com
> ---

Acked-by: David Hildenbrand (Red Hat) <david@kernel.org>

-- 
Cheers

David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8c4fdf87-97b9-43e5-8fa8-3bbc9bbe4953%40kernel.org.
