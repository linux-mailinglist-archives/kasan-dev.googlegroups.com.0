Return-Path: <kasan-dev+bncBDQ27FVWWUFRB45CR3ZAKGQEFHEJAHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E8C315A0C9
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 06:47:32 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id 128sf246653vka.12
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 21:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581486451; cv=pass;
        d=google.com; s=arc-20160816;
        b=DX1AxB8wY6gNZOTe5XIL7PNkSriQik4Eim2kSPcJdkAd5jqBqBf/56n56ZTFfI/3Jz
         bNtzAiH6EcnZTmQ1PXHnDDuw0LsfYWGw2oAjEWkde/zZYXpfzXy8cYCUe5Tql5/6O4Tc
         xCDMhsdVt+yrOOWFdPayy1dKY158wSG0jtAzIeSnBtZJvjFX1E+4uyRxdsjI9gHppTP9
         kybLc/VWt4yv8isdUK+9QSSVosjyhR6V3vqFfXol5uBCAvndiMUBxfx2hpZPcnT/p5Y1
         GE2FeClZhcDbBUji8fqDHNKv5yp7tZ2Z9pbD9PPnl2zY2bO9ups1L/ii1Mwjtih3DOJE
         EfxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=01i0eyB9b7HlB1351clW+9/KgIt8b1mhj9aSpAdNkf0=;
        b=hKB/Up5TXLY+e+4RemKDdmNKAQNGi3vHvw7zTEDnGXWcMFGHHwz3o6cwm+3y74fzTm
         Ii1u0ievG2s8wH7PXvh/TwIrYtd/SjRdM+JXRC1SUy4lAjbPJbglE3Eun/ZyBKIjPQ0X
         R2OlWNIT0FZzztYrFObDsfknfNz+KL8kvHFoj4lBCNSE7aiI/6tCapNIgsiOLFco/JgE
         XERZ3QU7a7EStFH3+WgIzMB7ZgvENLtWG/3UEzIVEATBWUZHJRrii6jzQjuydwb1gLgy
         ++Z06TFmYXxT089M3EXTB6ZoGEnUY3/L6+0yyeGHlNOU3+68Y0mH5oUW6ViRE3f4jkRa
         eKgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=c4McV3RO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01i0eyB9b7HlB1351clW+9/KgIt8b1mhj9aSpAdNkf0=;
        b=fNlTIYjh/qGnY2OXnWVieGjMoX97WDa8R0irb9mWkYgqDNfL+5YowR6TFmA2XxuxUt
         EPGr/zc4E6jpty9b8WshPtCNClg8VswU1o+yihbQXJK+IpAdYPB97OjAYrll+W+zvQaw
         tPzxDzSoFEeuXnq0rCgFLv6rI82FxwO7XA9nsRcDrUUP7aaMxLXrJsSVQSGhc7HVQBTR
         QfKExvPcKHEMzZ9e2Y66BHdbVF5uEsHKp47k/Fc865IuKk6thD0c4sk8fwxIppO/uPsZ
         sysfDpNd9b7mzWaWMMIX6/hEqkYiOtJqvLkf7bhkbMft5uYcV6rNjWUFs9Sm47LVHIVa
         IuFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=01i0eyB9b7HlB1351clW+9/KgIt8b1mhj9aSpAdNkf0=;
        b=AF55QACSX1iKsq5K5jEMro8mokuVD/8UMqbeZra380oTB/A3lGTMBwyubVLH9Tzj4g
         YuGZXbE/YVUV0ByUoBSd8Njvz7vuLVSLX0V1VpaYDuL1FD95i6Z85ENh4r5+v1DIRBY0
         j/u7GgpjI2oVmyVpydEuvQQ2pF4zNAPVjsMgwEgYDy671l7lTGn157zXLyZtKnFUfP4v
         nP0WpfDLV9ETSN2f0+IQNqRQrV341alQLPY7ij9zxQi9bMNEscW55kpGSFY4qPcCJ/+k
         LcvlAKitA7D6n5eLMMBDLQ62vyquBEcDWd7Vo2kZ42q2kHAoyErYsWtkd7a028atr2Eq
         XGZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXgX2+87z6KcIrGZHVQTtQu58TnCinADtmCW89pFPCB6G+NcAcI
	c05qjDDBZehKVH9jyXBTlL4=
X-Google-Smtp-Source: APXvYqyHxOaXI2UX4YMNomhxwQbpxlOIV9RYv1dP7Q3EvNo37jJUaI4uD6uOWnGmZQZ6rygDkduH1w==
X-Received: by 2002:a67:f60e:: with SMTP id k14mr10984940vso.14.1581486451183;
        Tue, 11 Feb 2020 21:47:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2883:: with SMTP id d3ls884862uad.6.gmail; Tue, 11 Feb
 2020 21:47:30 -0800 (PST)
X-Received: by 2002:ab0:7651:: with SMTP id s17mr3728205uaq.29.1581486450800;
        Tue, 11 Feb 2020 21:47:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581486450; cv=none;
        d=google.com; s=arc-20160816;
        b=sNOiROb4VjM3PJsxkviXY0bvs9lEG62lHD77bB2BQobBvGARP241FsyHhWt/vCmY6U
         rDXNR49y7ZQnig/M+BmHGj7CD4l3TSVohKS77q2fhFta+TPuS1haIkBjmtH8jT1+KXE0
         g6E3sFQCzIYQHpJHgpkv2HMC+2JVC9QUBfIEmnIz+GRarvAvfmugHIJ3JQ3B2GpPzKlL
         175a1GT/KRdMUbbr+9l/Tr3rVqC8XbWKOV89N6zAlWpYc6vhGBWt2iLeVXMSao0jkbAW
         AcJT5ApeI1foHO6Tw2tElKCrm1ie6iYutuxWp/PyK41szsvJ+pv9Dj1dZiL0i5efmfzP
         he7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6HBUqCa4lDkvWVMth98gkOfMDQFMmsNejhaPRJd9h6k=;
        b=SHlnhSQXbUELR8K+Ch0FuJhu2a1sCTDDCRRygltfVlZJc7NOvLNiJ5IKdqwQoXp8Lx
         stqHLO02Tz7fLPb8rSFy0Jne0h6aH0ehq/yQft8jS1GVHDJUBniPKOP7fRin2RFNZNPT
         +y62neeN865x6oW5vA7vq5j7WvnjmT634mlL2qNGvasw8dig8EITkOVI1wmMO8e9LLs3
         LFDlE/VKu1po27tN/2oG2QzpSQRxRDHklhePJuPnlpzO2QhIGr6xvo/UXqmE6jrW4ypo
         jhlN4i0Dw1GnXwuPLjl6IV9Amy2Z/6s7dC8/ZSk6hfDqJ/8HX3gF8LJQy4Ko/Jw9tRuw
         bL6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=c4McV3RO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id n5si306830vsm.0.2020.02.11.21.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 21:47:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id w21so600921pgl.9
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 21:47:30 -0800 (PST)
X-Received: by 2002:a63:5826:: with SMTP id m38mr10924864pgb.191.1581486449779;
        Tue, 11 Feb 2020 21:47:29 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id l69sm5969652pgd.1.2020.02.11.21.47.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2020 21:47:28 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 0/4] KASAN for powerpc64 radix
Date: Wed, 12 Feb 2020 16:47:20 +1100
Message-Id: <20200212054724.7708-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=c4McV3RO;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of physically contiguous memory
on the system at compile time. More details in patch 4.

v6: Rebase on the latest changes in powerpc/merge. Minor tweaks
      to the documentation. Small tweaks to the header to work
      with the kasan_late_init() function that Christophe added
      for 32-bit kasan-vmalloc support.
    No functional change.

v5: ptdump support. More cleanups, tweaks and fixes, thanks
    Christophe. Details in patch 4.

    I have seen another stack walk splat, but I don't think it's
    related to the patch set, I think there's a bug somewhere else,
    probably in stack frame manipulation in the kernel or (more
    unlikely) in the compiler.

v4: More cleanups, split renaming out, clarify bits and bobs.
    Drop the stack walk disablement, that isn't needed. No other
    functional change.

v3: Reduce the overly ambitious scope of the MAX_PTRS change.
    Document more things, including around why some of the
    restrictions apply.
    Clean up the code more, thanks Christophe.

v2: The big change is the introduction of tree-wide(ish)
    MAX_PTRS_PER_{PTE,PMD,PUD} macros in preference to the previous
    approach, which was for the arch to override the page table array
    definitions with their own. (And I squashed the annoying
    intermittent crash!)

    Apart from that there's just a lot of cleanup. Christophe, I've
    addressed most of what you asked for and I will reply to your v1
    emails to clarify what remains unchanged.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200212054724.7708-1-dja%40axtens.net.
