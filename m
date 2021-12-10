Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHFNZ2GQMGQEY7Y22PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 277A147080B
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 19:04:13 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcsf7074766wmb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 10:04:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639159452; cv=pass;
        d=google.com; s=arc-20160816;
        b=tcio13FE2es9yMXbQadjjFO1th1bW1C3oQGYZ3/2BuUJ/E9fVo2e8Ot0pf4bYA3ETP
         82NtY+TCtJxMErZDNwzvyAgwozBCd1CSlb8p35bhUHX5x9iOhIwsDWaENSRtUV4zspmR
         PmstY3AlxRBZjn/eAe3seO1F6nZtIqB548oEzEOsCTw4d5lGPIhVlHcwPjtgNLXw8yu1
         GLJy5s3iIm1CM/ZsnwYFmHRBDByw5GFNjIubThaMVLegLpa1UOJn2ftqE+teGlOXBVaZ
         JD+e/NfqSrQH0PxgJ3mObgDNqaV6J/9i2+NZwN8nALtXVh0fXKd/3VR9OaaRXKp+sP0R
         zofA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=He1jdRqJmdFguv/Xu3VdSCBiaigM5jWamqU55psWbfg=;
        b=QtLLDnlDB8eHatX8AnIlgt12mcQrMA2VPkc0Jicv74nL6DBgACyfGoDe1mNTefk7cp
         UzDa4MZhvyi6doBH4FKJSv/rvURZE1YLSuL7ezqsbusCqZvpRT0ehHKiHDak2I48Zrt0
         lx5sc0VicuwyMJmEOM39qreP5qQx2kz10ZRdL/0vQCzcoHvQPZ0+qoc+lK4oAGOzNNWX
         mVYKtk15FXR9+B+aQ8ZiBmWo0OSOWe4CiYDnMp2e9+UyYSk5PryhMZ4+nk87vrpHbWeU
         EY8RIEigf37vs8abWmtqpgwpEZ8Dgj5NZAlsVyMUoLKdCIbDnuDkIx5zYwouRHtHYYKU
         s+lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=He1jdRqJmdFguv/Xu3VdSCBiaigM5jWamqU55psWbfg=;
        b=a+8jZn8DU8I2CTaFbzLjOOV///alvm0L5qreyf6EoLA0p1fEUe9Wi7gbcEVd4f5PT8
         fcUqeFyCbLKRWdzyCh7FImK87f4g6uxIcQE05zeNhKTVxRZOyDDqdg/QpYKjz+acF2i6
         fRuT1UIPSvx4tZBeY3AUymEx1kC8LJbBfhSPjZGcdisCHwCd6ZtXVz7WELcZ4RPPp/l8
         ZCcufaw3oZuimZ/2b9cX0KJeEYgdm6rjrHRf6YAMLVXWlJP/nrzAOASxFN06WjI0ci/y
         2kbRJ6STGFu0h42w4XJ1Jwljh4GPiUckNP2iWzE4kNqcnc/ShCuFd5KCpTIHlPLXwezn
         lrDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=He1jdRqJmdFguv/Xu3VdSCBiaigM5jWamqU55psWbfg=;
        b=M3xwnbOwsz1SLvaq5TJ/MscQqepzdDbaB55XylprsyEPwTFx6eWtehG1nMW8omU1TF
         oPNhe1d/ynslJvA4gK7Ho5aeQCC6nID3Uz/E8FlGE/NpJgOAhobMcqfmG7WVIuk2oOiL
         r1/htO/b59wZvswNbtwd6NQ4nCQhUk4WJuuUyRthlRRhG4o4g35fVuXqs+yIPw5tQFOW
         orhZ/RG6CN3J0JSTCoYT+B7uuen7yVFOeoSZGAnPUCzA0sNIyKb59F3ZnTtqrvuCg+ha
         bTwIkYMZW6R3KPm/A8yldfxmYVF2cmyi/5CEVnBs6w7I/cjNur2YLZSi0JRvDyHrjfP+
         hxbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xf+ZU7nQHfubzvbhsmDm3g7UnBlNqsFDAWLKQIENCJ0+AswWg
	YQv7BtUhDESsMimV/rrqteM=
X-Google-Smtp-Source: ABdhPJzogrSGeAHH9atO/oEs4oUGVKZ/r0aF9GwRzTsQ4rsxo2X0+gH4kQX2bBddI45ZMpAEO6gGhQ==
X-Received: by 2002:adf:f151:: with SMTP id y17mr15793109wro.153.1639159452753;
        Fri, 10 Dec 2021 10:04:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls451314wrp.3.gmail; Fri, 10 Dec
 2021 10:04:11 -0800 (PST)
X-Received: by 2002:adf:dd87:: with SMTP id x7mr16011587wrl.158.1639159451446;
        Fri, 10 Dec 2021 10:04:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639159451; cv=none;
        d=google.com; s=arc-20160816;
        b=ZYU91Mf7MbgUIO+JAz+aKtNX79O7kevI8gwKnlaVqdPf/C35QYzx9LRk3RtkE/J13i
         D6jTkZ1mNCFsIzA+DU22GU4d9SMo9ZDhgYTip7wdDuuVH/YAx+oZQZMJZLkxFz1/9Jmm
         C3q5Qhr8OsHWoGJM2qjLYuY7O7zmXuLJL55ztsRCDlYAZGrU+wfknt0YtWqAuiIDZbDe
         eSFOGXwIw5Wzwpa2M0qoM1ZxJ7F9jd9z36zcsJNKINIOXhnHif1wGGkH3TK/FJ+82oR4
         3QqWYLpMQJX4buUrP2mOCaB/CLkIphJafllUdg31hmVT6DJfeOPzNMEnTyRVXW3oX2No
         AUMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=FskR9tdTNNRg6po7zLqj00km5WgWXWOr68EDhluLiyc=;
        b=ZMaBbQR0Ugyl8wPXMbzDTxzCqUpe1+boUnvN6doja05pin7a2nTN8lni6OpjqRLZZT
         AsPUB5AhuUIH7V5PiCJry+sOH9TvAHPYJJYV70zSdIgjX32t607jx3+DO6J+0AHTtuo3
         GnCUOdI9V1l/gGAvcTM5I7SJsYdpVe/9JcvZdCpe9GyetNyO+2VMfGlTlFwEw3Ss8LCY
         nQc/vtUv6tZyU69h4dQWcZHTCmX035q/k0s+WMB1sg4B5eJfQ0kmTlB2NSHYmJGgh1nl
         BzgheH1fbc5uNByE4TmIkD29K8w/qXtwLiKqop5PKErUhdlJ9mHzl0S48OHI542RrMtj
         CEXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id o29si419349wms.1.2021.12.10.10.04.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Dec 2021 10:04:11 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1313DB82706;
	Fri, 10 Dec 2021 18:04:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EFF83C00446;
	Fri, 10 Dec 2021 18:04:06 +0000 (UTC)
Date: Fri, 10 Dec 2021 18:04:03 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 32/34] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Message-ID: <YbOWk2ywaZpgpmeW@arm.com>
References: <cover.1638825394.git.andreyknvl@google.com>
 <4f56dd2bfaf945032a226f90141bb4f8e73959b7.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f56dd2bfaf945032a226f90141bb4f8e73959b7.1638825394.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 06, 2021 at 10:44:09PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
> selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
> select KASAN_VMALLOC if KANSAN_GENERIC is enabled").
> 
> The same change is needed for SW_TAGS KASAN.
> 
> HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
> they already work together as is. Still, selecting KASAN_VMALLOC still
> makes sense to make vmalloc() always protected. In case any bugs in
> KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
> flag can be used to disable vmalloc() checking.
> 
> This patch selects KASAN_VMALLOC for all KASAN modes for arm64.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

I also had a look at the rest of the patches and they look fine to me
(even the init_tags comment, feel free to ignore it). I'll poke Vincenzo
next week to look at the patches with his co-developed-by tag.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbOWk2ywaZpgpmeW%40arm.com.
