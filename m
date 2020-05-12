Return-Path: <kasan-dev+bncBAABBL5D5P2QKGQEZWDI3AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 701771CFB10
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 18:41:20 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id c14sf6094137vkn.21
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 09:41:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589301679; cv=pass;
        d=google.com; s=arc-20160816;
        b=uoUcIld5VUcBFkjIwv3jL7YljfRjrSt3LJaizo9v8ql5ZyjafZlF6tv4/z/K1Q8jtg
         0N8OIZOMZCjA1b/3o4uUPLz8o+PkOXGqG64bC+Zz+Y78e4w0QQ8QGiN9Ti+3D9UAuAsj
         mqWF82KWRXVGA98LwzHfbqh+5pa17Lf0+PD4Num9PzSZON2TZCyxnTzimt19N5m3G64y
         Ld/ubUbKNtfnHyFXfuzMyBCrd3Lpw5QGrXjbvdw1GGKY9xuTCFQbHlEwRMsgyXT6npNX
         b7cA0rfugkdEYwHJGg6r/GcDre+yInHhlnEjH8BkizuvhJ+J/Ew//M3vXZkrXgTB4yB8
         hcvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2fK7uQvnXA3Hp/dE+WnDVwTqqJR5XzXDtVPDe15pHf4=;
        b=dqOua2HXF3QI0LlbZ561CRWk3ALS+GkzrkQGab1rQns30g0wRVGTSJv78+h8SBJVmd
         eg5d6/tQ9bZuvpZSzj6QYyfrttWbCg/+eQc+9KWKuZyIYef2TD0EMpmWNIpduHdFKToi
         0roOc2BUQHKPvu6yYLbiERJRq2NP9SFM4tAXSlkUC6sPhO2uIp655r29rNv2pD1sfKCF
         e88hwIpGvsBEEchwWsImsM61WD0AJhjppB6c2FkpJspMjQlm9m+MRiCajW6MJ8wuoLkt
         TJFnygykPEq4zjRgBRy0XHDznTuzmJi4XX1WEiDQUY88fSvWFhw7njVhGGxZd07271Ij
         z5hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CWpg8cTN;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2fK7uQvnXA3Hp/dE+WnDVwTqqJR5XzXDtVPDe15pHf4=;
        b=QlxtQijrvBxeZopaxyO0FiBLUq6kz/FYLi1LHeUEi8gICi92UprwIpXlGw5CJUUztZ
         1utoRh9b12RImPXDDcMijfP+4WcQ4xy2djDzSmQDEnHu4fT1sVUwu1IB+3h035jjwm2r
         TtKhfx/GFGHSZ9dXa9NeO8JcSw1mHTH/bunrmhV/wM4oI3A894EPedFPxGM4EUKXYR4d
         eGi4GU1pv/CjzMphvmCyuOKmFjg1e3dw8+SfDZwXE5PBKqrlwub538bweuxJEDDGAy8e
         DPNB4D8sUZAgXhhDoW4Ko+PbB57KQ/0G2EMOGRN/yNjipQ1z+ZVK+PRHgscc2MrVeT74
         N96A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2fK7uQvnXA3Hp/dE+WnDVwTqqJR5XzXDtVPDe15pHf4=;
        b=P07nIseHHMgaOR65EsFb5SqR1iYbnv8iLLgkXv+T2NT8A4crpbMTXEBCQPeaxiZKoC
         p638vAmFGU57GuRvxu2wU75fdSHjQ7/wlSlOO1pNqMtNf9shOzXHcZMTmPmEWlO0bm6u
         zCqQmygsZP/8IONh+wRzDzipXU/fac98t5TtS+w4FVFhCEIBsX8N0GcTuBnA2pqYE4Bp
         vdyQpCODN8L4eMbe5lPWDrdD4pbSfY6GS0OC+fvH+kPg7Ec5mojr7fviVG41e6ZGiLcu
         1BlKvQ/CUnl7yoEYmsCcD8kgTiqNSFapmk+w3a3BCeciS1yPDTarRHzI/wUckXOwRyLN
         u7+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuavmiXSIs97b4mXtlf5Z0LXZncdPCXzN5J6XuUvMEYlkdMGJ0iV
	z8+H82s0D0SeDyyWbwk0Aek=
X-Google-Smtp-Source: APiQypJhOufsqx8dNDYqYfsxcTGnlWrWnTU1d6G6TKpC65OzprG/GgrGY+ctjeG9SA2v32KxEAGXEg==
X-Received: by 2002:a67:ee96:: with SMTP id n22mr16416220vsp.29.1589301679454;
        Tue, 12 May 2020 09:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f316:: with SMTP id p22ls1631704vsf.1.gmail; Tue, 12 May
 2020 09:41:19 -0700 (PDT)
X-Received: by 2002:a67:e9d9:: with SMTP id q25mr16771848vso.27.1589301678986;
        Tue, 12 May 2020 09:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589301678; cv=none;
        d=google.com; s=arc-20160816;
        b=iJqneMZYPhZqnER72NPT5a0OcsCt1HMO98qYS8wGDDpNsC6rXpkLK9evEzl012+L/3
         1Et80kl065/lEWW2aRmJQbDxiBd5zvk02zOgEfIFmaTyZ2iNu3n9VfibPdThpBIgqN61
         0gVLRSahFt1Xz94w8P6cannKIm7NnMCbCaZOdNSest1nkuFahwDnUhhfAbrfqovd1lKE
         bv9VP+F9oegyOzZCXOnunRpZjib/RJnbFbdzMFKQzqZEkHrF2k2LK9gl1/MxqXRaZ/rK
         ZVzmgobu7nz5yosCTavvTV1RXoJc+JmvRj0CR/7hSQRcq2WA9jIzP+GrIzQfCXzlJrIM
         P2xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ryTOttSGVjTJCYmMCQcDEgrysS1jrc10z3dqeJ88ZZ4=;
        b=C6/P2CsE5qguiUkwhPDRy8q6WMgpKwlw9ACyee+ZFAEDM5zsYbuXWxa+8f3yp/QUlC
         MfsKK6sVnmEjQYrG1YFnmsGkSsfayp3jeAiBzRe08Ce0sYdQKapIXejf6kCzLNeqxrS/
         SDMZx9aJi/2Y5AFxzClN9m4vVSA1A2FzLyTTiIEJFc0iUBuDwrl5H366CD6pLXoj7Sy5
         bVzvgdN5gmMhtPACstNw8Awq1K7noaqJMlz/8/hn7+4duTneZXLI38W7vPpM1Gh65PpS
         DC5vXE0kDeInqW7iBt0hFNQEqDLQ+q+Y9u3NMJEK1UUhLH/0btUGk5h8oN4zCjG2/QjJ
         fiMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CWpg8cTN;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y77si692834vky.0.2020.05.12.09.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 May 2020 09:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 358EC206CC;
	Tue, 12 May 2020 16:41:16 +0000 (UTC)
Date: Tue, 12 May 2020 19:41:13 +0300
From: Leon Romanovsky <leon@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/3] kasan: add missing functions declarations to kasan.h
Message-ID: <20200512164113.GM4814@unreal>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <45b445a76a79208918f0cc44bfabebaea909b54d.1589297433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <45b445a76a79208918f0cc44bfabebaea909b54d.1589297433.git.andreyknvl@google.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CWpg8cTN;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, May 12, 2020 at 05:33:21PM +0200, Andrey Konovalov wrote:
> KASAN is currently missing declarations for __asan_report* and
> __hwasan* functions. This can lead to compiler warnings.
>
> Reported-by: Leon Romanovsky <leon@kernel.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/kasan.h | 34 ++++++++++++++++++++++++++++++++--
>  1 file changed, 32 insertions(+), 2 deletions(-)
>

Thanks,
Tested-by: Leon Romanovsky <leon@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512164113.GM4814%40unreal.
