Return-Path: <kasan-dev+bncBCT4XGV33UIBBOFISKUQMGQEA5I4E5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B607BEF65
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 02:00:58 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4065478afd3sf33830565e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 17:00:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696896058; cv=pass;
        d=google.com; s=arc-20160816;
        b=OhIDLaLEvp6/KHD3W/Rb+ZUbZCLCvJBBbpRTdFBifRgAsORtYnrz2UG29U6t0IwaH8
         lyJXYCW6bEMuhiIxb/WIqlH6daUHUFPjwSZA/VOY5cQohZ56HM23oodokVmyWib862i9
         k1MVCBze5E39KNGCCn5v7AH0Zr03h1sxwWZu38vLx57gRS3cl49+RIRGiWY9Tg0eD0l8
         G1tDiqlpAfK9/BKt6nBZAUv6tlarCY07IZkbseL/XDnSIOmwtmmux1PhgAouKk0zs9T4
         OKW7L03I5DVPxIOBzvlhIsK9qYsacX+EGzfA6CBR7X8wYhbYdMaYsbFMvCA44hnDjjqz
         UpcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=860Cj9pPlqwPobSbVGaZrvofwTR7/oFlBN1PcScfqls=;
        fh=tzl7VynDwwAEKRbUREVdeazSBsK/qY/13Co+MQssVLQ=;
        b=0ThCbSDvgrXxt1sOFQ5F2aebEjClh0O/yO1GQgwsBdp7BZeQ7jCn3YW8NP3BIHb/+X
         HoRb4P5yNSmkpUywQB5uHoocl1EjDAU0phMDyiNXtr3qAldaGwpGcVYEsi3cz2yx+d+V
         xdwZy/QfUvJmSy34h/y8d/XPkyK8ikEtlXjyozc54NpHnyfuUm4ETcKBO0YZoTlclPAP
         zsokP/ayibGChjgDpWyzkZ8T4gNmzg5SHZjsgg/SRaLRzJeZ+UBbd3CimYH96s6kKj+E
         SZxYI5QPKwEqwWL2PePPbZ0mKs3it/9knb6MOCZ32Bebx6AxkfUkqWLJ2YGLLR+hR4gL
         +7qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RryLjpiV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696896058; x=1697500858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=860Cj9pPlqwPobSbVGaZrvofwTR7/oFlBN1PcScfqls=;
        b=Rj4YrDiesHSnBxCxq1RLNZPsbzvzky0ey9DWDWYZQINyhSRSXDneDt2ZBZaSgLr3yY
         PiuEVeZP6ynovRd41Q454dSlTPx/21hYdSKtkvRL4hgCgwE6YnPAPaJ0lSm56VuHPORc
         QFOtT1BlI/xkzIGZuI0dlx7M0Li4F1/XzIlEBv33TIBt8ziaKNhbnsM1W7Z4InTGF+Fw
         WueHAJAiT3QoiSKnjrCspuq9hsRNr/tGXYhtjJqWmYySqzvgx7E5DzR30VMGKymyJV6q
         t4wAIYupOgOq5FZUxCMAfa+1WUUc5aoKYZrp3J41h1M9VhU8gofMwsT+gqnZWEiMgT9V
         8Biw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696896058; x=1697500858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=860Cj9pPlqwPobSbVGaZrvofwTR7/oFlBN1PcScfqls=;
        b=qO4I+ZFtv8brPCYIds/ehAslgo9YgKFmNyyQ4+3hVKsAHpUwb9OfHobC7AuQQVFgGj
         G37L5gWJph6A8gHo5gG/IjswjGGleQKpN7eMczKxLhkolxqu5olklrgVf94fIUHNS1Y0
         yTzfN98ESdjUhga/V+Jjj57zgJagwiQGPAsFW+Ww7uxY3uASDwdXk7AXiWQrfT0xAiLW
         re5wXqo69P5CpYjcsHbm04vcRx5g9lfmChRZF4rKbz8C15mLMyXDWcedwfTAbgOX5ZBV
         BINrHnt9lfLeN8zo65iNlHm+7/fmDf8CWofhQ1RBl5hBOjDI9SYWPfzLhx0+pC3LJU+w
         JMag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzGaai+oXkqwGjSP2GUG4Cl0UcJGHB+txBa/7ZN8bMOLiNxNlBM
	Tnv1F2uzxJI95TWn1Zi4CRE=
X-Google-Smtp-Source: AGHT+IGYiKDyieJ0lo04oofQZ7ywFrtdGD8Khm7djQXEAtx8FgQcfgKtOd/QhX0zmIPJTmWtEQI25Q==
X-Received: by 2002:a05:600c:b4b:b0:405:3b1f:968b with SMTP id k11-20020a05600c0b4b00b004053b1f968bmr15560053wmr.21.1696896056970;
        Mon, 09 Oct 2023 17:00:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c8c:b0:404:7eae:e6cf with SMTP id
 bg12-20020a05600c3c8c00b004047eaee6cfls2798541wmb.2.-pod-prod-05-eu; Mon, 09
 Oct 2023 17:00:55 -0700 (PDT)
X-Received: by 2002:adf:e541:0:b0:317:69d2:35be with SMTP id z1-20020adfe541000000b0031769d235bemr14247453wrm.30.1696896055071;
        Mon, 09 Oct 2023 17:00:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696896055; cv=none;
        d=google.com; s=arc-20160816;
        b=NMpEsUUJ/kbGzzK8BX5gK/dBNaHFQuEeTLTbBE8/ELI7dhGbVsLfPcsy7/H+A/36Qk
         CJz5wg4KHPrGsZbwI9s3SLRig8Rz7HqDh9YOXzYEa9KvjWmfWYU7lRIdX+TUJZlw96Tn
         3sraV5i8BjqFy/4uUJGnhy+Isil3GO5qGLRTTIsOt7JtLNTRdMw8vPZ5jG0eCYQUetu+
         eTAtTZyUZdvLuuiVmkK+Mqijt+fqg5jENMItJ3ttqNJZdlK8aplayix6QTBoSFNNyjKX
         yIbL0tw0/lcFOhVssAXPlDEOjBvwsxED/WVQ0GhjoxpwpnI+0vOo8zHjLGshSJBT689B
         HAZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=m8wElF7g5syQ7ht8CtQXj+FlFUUWeOsXPs0gqy6jQ4o=;
        fh=tzl7VynDwwAEKRbUREVdeazSBsK/qY/13Co+MQssVLQ=;
        b=eSpd5VE6erb3poeFVjH4q1N7Rbr2/Nc4Lv/XIPES0un6AQK6C8wrloWMolpv9bdoaZ
         IVBVqvjRVs5JIlqpi7/phaT9B+I+24p4hmfNHsz0MfGKRCd05UoXKxaclWLXahRbOirT
         5MkBOGYd/VwI9U/GugvGoyBm+7AMNCdAiBcY4DaMxCnyKkyIUuMiwBD8ZInpXzajMcON
         5mSv98JEvLsBPoKqEJjTlvmBlzLqNS4DLTr2sGjniuXXr/alKKLeF2rGTF+ri5DnGgOs
         ECU4tO1rklv0HjPqHQF04unPQHE4nZfYRsfpbYOtshhEnRxfJgGHUABevVHj930+SqdC
         HVxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RryLjpiV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id ay17-20020a05600c1e1100b00404ca34ab7csi630383wmb.1.2023.10.09.17.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Oct 2023 17:00:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id ADB56B8092E;
	Tue, 10 Oct 2023 00:00:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E7362C433C7;
	Tue, 10 Oct 2023 00:00:42 +0000 (UTC)
Date: Mon, 9 Oct 2023 17:00:31 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Haibo Li <haibo.li@mediatek.com>
Cc: <linux-kernel@vger.kernel.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
 <angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
 <linux-mediatek@lists.infradead.org>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH v2] kasan:print the original fault addr when access
 invalid shadow
Message-Id: <20231009170031.a294c11575d5d4941b8596a9@linux-foundation.org>
In-Reply-To: <20231009073748.159228-1-haibo.li@mediatek.com>
References: <20231009073748.159228-1-haibo.li@mediatek.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=RryLjpiV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 9 Oct 2023 15:37:48 +0800 Haibo Li <haibo.li@mediatek.com> wrote:

> when the checked address is illegal,the corresponding shadow address
> from kasan_mem_to_shadow may have no mapping in mmu table.
> Access such shadow address causes kernel oops.
> Here is a sample about oops on arm64(VA 39bit) 
> with KASAN_SW_TAGS and KASAN_OUTLINE on:
> 
> [ffffffb80aaaaaaa] pgd=000000005d3ce003, p4d=000000005d3ce003,
>     pud=000000005d3ce003, pmd=0000000000000000
> Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
> Hardware name: linux,dummy-virt (DT)
> pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
> pc : __hwasan_load8_noabort+0x5c/0x90
> lr : do_ib_ob+0xf4/0x110
> ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
> The problem is reading invalid shadow in kasan_check_range.
> 
> The generic kasan also has similar oops.
> 
> It only reports the shadow address which causes oops but not
> the original address.
> 
> Commit 2f004eea0fc8("x86/kasan: Print original address on #GP")
> introduce to kasan_non_canonical_hook but limit it to KASAN_INLINE.
> 
> This patch extends it to KASAN_OUTLINE mode.

Is 2f004eea0fc8 a suitable Fixes: target for this?  If not, what is?

Also, I'm assuming that we want to backport this fix into earlier
kernel versions?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231009170031.a294c11575d5d4941b8596a9%40linux-foundation.org.
