Return-Path: <kasan-dev+bncBDDL3KWR4EBRB56SUKFAMGQETWV5W4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E64E41184B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:32:08 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id p12-20020ad4496c000000b0037a535cb8b2sf184366751qvy.15
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:32:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632151927; cv=pass;
        d=google.com; s=arc-20160816;
        b=RNHjOXSUsqQXtJqMb3OrnYYtk5MQSBm+In0PNGIzoX3G7qfW24DX47PaxxpEXqo8dA
         ACuTWC3pnXqrY/ukbc+t2N2LUr/N1pj7wMHlXLVGzsrfHTNgANbhz3QHh8ykQy0xHosO
         7TEMhPteCGDixEyK6GoJhjKkgoAvYv5fu+1cniMYGhwmpQL4Lhuso4orbmDp/uqTuyAf
         uQbMMmXFWHkOV56V05YgrqXgp/B51gTcI29r/2YzyQRqgtdbQzjqQD7UqQsR2Cs2I+Qw
         xFin7hJQRJnZv4D+gxjOaJqTgPCTHk188lFLwrMaFwLROBe7e6iKxmmmFKZJbl5cswNS
         0ECQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9mot3h22bFtvA4eaA8exswnjLpS5ft3m4/+/iY62Few=;
        b=1AN97h/xihsRj7vHd5F0TAM0HWBkDMuWH6876GrWXSS9N//gAWnNOktBWurfnk6fi3
         S4rd/ZyPaqQcTLV4PnNVrknWMFNAxRtX+RR42CgIzsJH5XK0QpgYSQq4/+YT3IC7NrMw
         JL0RCvI9JZdP6QfYmhfNi7AKNXNokmW9JfWV18efW3h96On3U6OVSJ1XxpiHbPQqoTtN
         8v14o4HtXzPpG3ibWHrNG7fSSL1kDU5pcy60Z6ctMfw8x2eOThUrK8Xf156+C3F6Le5K
         N7pGUYMUFjA4LFWrl6NWJqR8WySdw2vl0ue1RlmnyK4LdgGu5FYume9fupJk6yHVDqXb
         fbdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9mot3h22bFtvA4eaA8exswnjLpS5ft3m4/+/iY62Few=;
        b=cJhlMiQH9koUByuK3yFbJpv/r4HZ+F/uvbHKi/Q8oxLJDH38BxBM5e2uk0M9rugeiD
         AvhsOAoU0ND4i4th5u1apR0N5CqbUdzeXnXiBf/A4l9XZ8pn1RotkVkCMUnLaQpUG92l
         aCEr0P6m68p8e49zV7jE8q0XXeLdux1x9lkiyX12ytRGpi8ObF0dzpM7kk/7l0uU/bCQ
         V5PAOdh8bhegBDHSFAKxerHEHDftot1f+WzT2oCH+SHqjquIOEirG6MalzQxdiUGa77B
         RscIY7KUlwx7iOhaym9fQzpWbUl7FPz4F7wVoItXfu30ov85LrYKNxR/tijzVJAkUrQo
         lCBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9mot3h22bFtvA4eaA8exswnjLpS5ft3m4/+/iY62Few=;
        b=V0sXq/dAkzLdoCDdp4/vydhhuM+FjteDxmSSKW7O7T5ySrqo88azrraYAM5GjBxUbj
         A16n1SwQzdKsU9S7MP+aVyKj0vxa2oaaA8WqLUq6t7McylRAmWqOllcbJnyrlFTUoAe4
         wlZHUfN0/EgMVvF8L9p4ToV8WpatNOutiZXdQij/+nUSV9hZlpmMwzQJbyNwFp6ccOjt
         D3Mr5T3rrZk7kh+XEgID9Xf0UUy3TiXnBr66yxStTZgm6QoamFZmpDZxiCTo/4IaNRjW
         BoPjEm7QHcJok8PxTXkqgDlBhqvROocodMG17JMBkQSX1U8guDoWz5/0fd6c0Ac59ZFy
         oDCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MEVI15TCVm+fWDJ7iJcGVqMfmHg684ek9U1WXoqIQoiBGn/m+
	RJdhwi9nJX55WF7prwnKzbQ=
X-Google-Smtp-Source: ABdhPJymCTDqW5XE+rS5sqXJ4SNOXGklH9royGNa1OZqSW3W/s91BR+wJ05Za6Eg+2TD54G7kAigYg==
X-Received: by 2002:ac8:4149:: with SMTP id e9mr23432934qtm.249.1632151927244;
        Mon, 20 Sep 2021 08:32:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1582:: with SMTP id d2ls20250193qkk.9.gmail; Mon,
 20 Sep 2021 08:32:06 -0700 (PDT)
X-Received: by 2002:a05:620a:2298:: with SMTP id o24mr25224654qkh.235.1632151926746;
        Mon, 20 Sep 2021 08:32:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632151926; cv=none;
        d=google.com; s=arc-20160816;
        b=cSiZzCnCSF8jylhoJr3jdVdr2CsCIAIZR7RurO6DX2goq1zvkzZVDka+42Wkba2+4c
         m+mESj1iR/dcVFKKLc/Cs6Tvgap3+xC50qd03EEhTXjoHkycWa8BaSR574rtPoCmvWRx
         JAt3F1kgtB63nscqiKOvDGtxZagA/2tA80XVo8NZu16m3xKNWZ75zsH3dElRyNEtjIty
         11FXo2pz/qwrJCkbn4loheN1swibu67HNpkxQGztyJc9VKGjXSkwFKga/GWW+zVmTHpX
         KR8roJ8cXhcH+Kruz3IaLQhlIF++MzYZp13r8n5hSQRS0r0pqr2STBIDL5fqCPR1CWn7
         i+rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=KPlZ41VEsC01EZs5cuUfJYSy4FOwhrwbFw/HRpiiIN0=;
        b=auVoar8tKGKeul3TKdAGBJHPRu6wZLdzVlLJJdJ164u8Q0FWGo2kTuaDIEGVWV/gqW
         zdjntSze1J3HUZnGJKw3RrFzSWN/MoOSRh5q2dORixslUxxIQL2ssMiX60IkUJ9mTiOA
         sYye3mT/Ma6Obg4S3zOuYRaCYJGEey3Ab/8Y1Hd0/AUj5OdgPXyu4yMnbt0Peu8kDeUr
         8sNWeD+2CAU9Ut0AYGuPjIxyppSkGubQJai1D5Ai+VfMF0xQmYZJyMxX8DnLyIheBGOD
         /iHa+yL9NGcnj1C4ucaXUOZ0F/Ukx2r13ILzSvc3P9MrhWRaZT5LC6rDHqCHPTsNke80
         MlmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f13si10210qko.2.2021.09.20.08.32.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Sep 2021 08:32:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 415E3610FB;
	Mon, 20 Sep 2021 15:32:03 +0000 (UTC)
Date: Mon, 20 Sep 2021 16:32:00 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
Message-ID: <YUipcLV5CZ4x1i+1@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-6-vincenzo.frascino@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 13, 2021 at 09:14:24AM +0100, Vincenzo Frascino wrote:
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 21dc03bc10a4..7f43e603bfbe 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -194,14 +194,20 @@ additional boot parameters that allow disabling KASAN or controlling features:
>  
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>  
> -- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> -  synchronous or asynchronous mode of execution (default: ``sync``).
> +- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
> +  is configured in synchronous, asynchronous or asymmetric mode of
> +  execution (default: ``sync``).
>    Synchronous mode: a bad access is detected immediately when a tag
>    check fault occurs.
>    Asynchronous mode: a bad access detection is delayed. When a tag check
>    fault occurs, the information is stored in hardware (in the TFSR_EL1
>    register for arm64). The kernel periodically checks the hardware and
>    only reports tag faults during these checks.
> +  Asymmetric mode: a bad access is detected immediately when a tag
> +  check fault occurs during a load operation and its detection is
> +  delayed during a store operation. For the store operations the kernel
> +  periodically checks the hardware and only reports tag faults during
> +  these checks.

Nitpick: I'd simply refer to the sync/async which already describe what
the kernel and hardware does, something like the tag checks synchronous
on reads and asynchronous on writes.

Otherwise:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUipcLV5CZ4x1i%2B1%40arm.com.
