Return-Path: <kasan-dev+bncBCT4XGV33UIBBLELRO4QMGQETZSOWKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDEB09B70AC
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:47:57 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a4e4c723c3sf9686215ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 16:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730332076; cv=pass;
        d=google.com; s=arc-20240605;
        b=aonzmywsWVTi53pp3TGcWUTSTYMSWU6iwew0cKSL1McCUc6OIHOfaqvNopGm3GkNPp
         S0XW1fv2ElhFYGgTD6GPKG2Fa4X0YOusG3+Ttz7+x6K9EXYVxc34PhGFtMbsqEj/bkms
         oyxWkypzPMnGp5zyZy/8tt1eTRlc3DheXGz6Q49egFBI7eR7FDCmTPWXU/D/peX7Z/HD
         VkHnapQif/jK8UZOJSP/fN4fqULi1rrZt01eWJ2AJyM1Jca/PMjKnD3+6UZiXv+95QHx
         bwXbJDX7BwD/VmnZ4qc1FMLXGD2QvcDHJzjCE/dFwBz3SV248z8xG2QA87Dtq5HcSWNh
         JBDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xw0JtHBQDM0T1nzxe1RHvsRGHknfTyAsLFeRDPAvqsg=;
        fh=bA1a/L/uuZ5A2uaYsfc3Fs+VO2hiQ7f93yQ0Xca+bOQ=;
        b=MSlVh03nyQbI05HBjGyGa4ihAWAGUZGA3DA0ha6lgvuYGg9Q8HhC78FLaelEokP+Zu
         kMThQXJ/Q9ZbQfBEerDNrwav2ke2R26QeuY1jRfAhL2dP+v67rv5SdMLfMJee/QUM4TS
         dAD0FSw38T10kdCj4imWL+B0LJYs4dsnZI4HgRi3vtS/yPq/Pg/24hDwgPv+WJ+Cxtjr
         Tcsp0UieFX2alc5jhbNRIU4MRB0eCMIFx9i7xFhtYL60P5JW7i9VZhrFpKf4/VIjdYKS
         tHwT3CtzXML17RxcVFEtqmE/xohQFMCj11EeSHQzEj29+ApHYvtrHmJTJwr1ZVmQ6hGW
         phUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KzprbEYD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730332076; x=1730936876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xw0JtHBQDM0T1nzxe1RHvsRGHknfTyAsLFeRDPAvqsg=;
        b=iEJOldn8qvBUkcQI0kUfsWbMa6JbEalwZnlSLieM0OsPBb0M7NykGkjz7/HGpcOgaL
         gHqeLdHva5LplefGuj2wQJS0W+v7tjUFiObP1IuOXdVEXU9k/n9JcxkPiWOgvujt0RkZ
         CQK9XrdYRdNMJRyeS36iI8xvBOSPmxzMCNI5brp4AUagt2EZoufbG90dn6vWBv56Q16b
         DVN+WlZVE5SDDVmIXuqu+iGUcb4ebTI/FI2Wl55WYtzMMJhAwl3tpkiGtQ8INwIGGj5b
         i8kPzu78fEoB+HQ5S4DIvojrIdRFzxrxouI1U8KsUYMF63gGM7N/tu2VrIe9Ln7xalGg
         urew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730332076; x=1730936876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xw0JtHBQDM0T1nzxe1RHvsRGHknfTyAsLFeRDPAvqsg=;
        b=wflt+EEPjlUpXrzIuOgOcuUzoJAq9iwy0fYYRJBmvkzysdub68+7jZsvcgPRE9Yq77
         DRb7XsDRDDN+Su8zafoEC5ze03kBZbuuit90pwWnGDEi9XB56nfimZjJW0XPnOGof3gA
         WgrgvtDZ0CGzZAHseBtwkJ1x56ThfcbsNupEBy9IovFPlMxxKh52iPDvJMTIOS/Ybu01
         +s2SlOS5j/ZExRbnGd+iZBmJv1Oc6mLy18DwHctz9MFTRmjL8vCR5fM4x3XLkKHCbSc0
         vI/BTkdvbZb7PQQmatUK9bWge1fjzjkUhGKahmoNX4G9+5QL2JQTXE14AnVKZ8bJdw47
         dZwg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFSDh9UEFXIbEdvdtJ2MQP+aJXBWNyRspQlL7ldLfIDibw1XIOhptoYzDEnRkbG3inIreLjQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy+UjizGfOxcAgEHvvjHhaEbcctRj3JTq/yOZPWLpSmhbGVjRGg
	njehTRr9+GwSWtPSjHjqypGt9WsafQ7UXyG5B58JA6b4mIjs/MNQ
X-Google-Smtp-Source: AGHT+IEXbE7Jwzcp2jum64k5mWu7X2e43QTbsYo9vM88tcCWb8D9JGkvMkt1GnYoL7l/k9nVoVH16g==
X-Received: by 2002:a05:6e02:3886:b0:3a3:a639:a594 with SMTP id e9e14a558f8ab-3a6a94a162dmr3548465ab.4.1730332076653;
        Wed, 30 Oct 2024 16:47:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d95:b0:3a4:ed5d:5799 with SMTP id
 e9e14a558f8ab-3a62810099cls1958065ab.1.-pod-prod-00-us; Wed, 30 Oct 2024
 16:47:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWO/7n59rNl6ezYSPB2IMSBufFWs+mTUqtPtFv4bIzTbzpZaHItxRIjm9ZNPFSdMWGh3MZQ1OFFUOU=@googlegroups.com
X-Received: by 2002:a92:d20b:0:b0:3a0:8e7c:b4ae with SMTP id e9e14a558f8ab-3a6a947d85fmr3333255ab.2.1730332075705;
        Wed, 30 Oct 2024 16:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730332075; cv=none;
        d=google.com; s=arc-20240605;
        b=hN+nTM+2C+cdJwEDwO81dwQnVnXBloI3HTvMwH3OSR65p7ZiirlB0C840oLXOWnoos
         9CL/0OeNXFNz5HInd63c+wzhMemZ4WKrYQyYvsd37EKjJict02XAc1yf/UeLM701jxbx
         aa4Uclbs2SA7xOe/6EW4F0FsZscQ3Ae+JJdkAKiRRocHhlsBqG7NECzSGmgEG+2fmF++
         B9UKvr/ZEI5XuYij63ZdjuJLPtKRVpVRZAee9VNOirrQfNNhcS08eFxPVHFAnJc63DS9
         XBuUjL5mQseqEzuNZmp1P7cpsBrdGwhYnQfm1aDAPckVAsf/zDFrsHpUkvwYuE5AakRw
         pgsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=G0KDOwoeGJMZbo/sAlYkGuX50FK2j+D0LW0wEHv64gI=;
        fh=tq4C/5C3DCcfJogqErcqTJcwqyqbt+p840LBzh6Y+ys=;
        b=Cle4IfWiGH7wtuloqatCuH3eLpDpluzP0vVIzDSOcf8ny++3Kt5U4F3R2WJRDPl0mz
         5BhQuppZoWfxNqTHrBbGZC8+n9b/RbmfzC99Aczm6s1gvI1U3ww4yX1NW2OgIdVctfVu
         NB1SbsC9FyOawxuFruVBKNiPA1urS2bFZIAzJrzLvUuxa4O5L+G7wwUJ1c/ZV2dHvOr0
         Pa/PfYjojBoEL0sEjLUh3Llzxm2kYk8+r8NigwO9mkLfnY5DmPODAfq/LSuckOONC/9q
         6yt2QGEz1Wv9+zr2hZZwV1OdwDKvFPTlVVN6VsGoP6zGWU/ouEudW+LmbTtuen7O5r1S
         8F2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KzprbEYD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a6a9a29397si82635ab.3.2024.10.30.16.47.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 16:47:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 2CE42A437DF;
	Wed, 30 Oct 2024 23:45:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D0C40C4E68E;
	Wed, 30 Oct 2024 23:41:23 +0000 (UTC)
Date: Wed, 30 Oct 2024 16:41:23 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Bibo Mao <maobibo@loongson.cn>
Cc: Huacai Chen <chenhuacai@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>
Subject: Re: [PATCH v2] mm: define general function pXd_init()
Message-Id: <20241030164123.ff63a1c0e7666ad1a4f8944e@linux-foundation.org>
In-Reply-To: <20241030063905.2434824-1-maobibo@loongson.cn>
References: <20241030063905.2434824-1-maobibo@loongson.cn>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=KzprbEYD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 30 Oct 2024 14:39:05 +0800 Bibo Mao <maobibo@loongson.cn> wrote:

> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -267,8 +267,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pm
>   * Initialize a new pgd / pud / pmd table with invalid pointers.
>   */
>  extern void pgd_init(void *addr);
> +#define pud_init pud_init
>  extern void pud_init(void *addr);
> +#define pmd_init pmd_init
>  extern void pmd_init(void *addr);
> +#define kernel_pte_init kernel_pte_init
>  extern void kernel_pte_init(void *addr);

Nitlet: don't we usually put the #define *after* the definition?

void foo(void);
#define foo() foo()

?



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241030164123.ff63a1c0e7666ad1a4f8944e%40linux-foundation.org.
