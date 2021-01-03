Return-Path: <kasan-dev+bncBCCJX7VWUANBBAHWY77QKGQE6XSMCSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E3402E8D75
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 18:12:34 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 33sf19913538pgv.0
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 09:12:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609693952; cv=pass;
        d=google.com; s=arc-20160816;
        b=uEauYW6cAEbKrSgzbr8yR6fnubsQEjwWmiq6Co9THMIwWMqmogRC33+nLv6wCu/GF1
         Anxf/Y7Ihpj0BJtI2zr5Y0FmCvtwK959/m6eWnAfQZ+0gg3LRlfbkf1NMfU76amdpVaf
         k6Y7jnW3SVvjYXvy55RFMi9I8EZmJVvek5S7BWuoBPELFZIXTBRGkqhOBYbBP1sFUv8h
         bDLgIBnLEOUp8oRhFXZA7NyjVEeVP0sXoaAjWDXsemgPjdQRnOqYQjrUk5rdFaTGpJnD
         tPkDfqo+CONuMQPIaqE/F4se8t0jSEG7D+Q/0vWf58ABeGG+VraHx81/9QkpgW6dgyRg
         +Zvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=uXYU/MRkYt3ZFgFmQVT9j3GIXeUXCPP4WaOyT4C4pHM=;
        b=nS9gq8Zzfg7tzz5uJksNbKKEJR7cxzQN5ItOHuVhHXHttESz3j2znmwEAfmoeGJCks
         DwK2sOpugZ85bIKZ87vwOhwxtntYiNqtZaBc7cmqjBbklV0AmPty7ReqW5yEZqW5O5oi
         ZVQsyAg6257pyPz4UGzwpQCRqt6C1bgcy/DYEZTIXozWB2t7h4mU/az9j/XFHpurl8vX
         n5buAb1yYU96C6RsRXTh4Ho82MIUS5okIn/2Wb06upGYy1wosU/kQOhjezYDes7+rtzP
         hDxEgWZug322rP7ARstlgMF8e0x6x0WOxGiTDwC7VKmOsfX9rbhV6yu8aiyboXqe9cUW
         pLXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=j9nC8spD;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uXYU/MRkYt3ZFgFmQVT9j3GIXeUXCPP4WaOyT4C4pHM=;
        b=dXluovZuVfIxPbVDG84Q6RoZECQfxvCvSD2KKgwVoKzs3f5f3Sg6j8JMbJ/aUhQig1
         y2SwAvCHwWQ67aBTGf6UTUrJC0ZRxm+zTIT5GLEph0Pej2nFn0gVsjFqeiWaQ0GQoceK
         PlDgpxoJRAtS9eueCgRVaSPT8Be6MNYS5ipRnlnrlT5TrytEczcaZPcR6LYyFcdxRRWW
         2J/emvlcUmvkWjWOUhxc94JmwOniMORqQyeAmwhjoxyPHtjks6IMnB0KX2535azEh6TU
         Rkvybbg/bdP5r2FOqoz5DnI05t6NYLXmN/H4x293IxrVQtyj5F7LJZLbvxZydTwFTewz
         c/hA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uXYU/MRkYt3ZFgFmQVT9j3GIXeUXCPP4WaOyT4C4pHM=;
        b=sLXz/z8GC2aQveyk6QJ8Qj0NHRe2+luhFHYUBMN3ezokP0FAWYIonKK6Eyd2Xsrs1E
         k9LP3ZLH15MRagTD3PBK7+vTLZHrkXUeUwbAtpNZhQ1tk3sI0tZNuHKf1QzJdrbCg1JI
         ddAiQm9j+6VolH8jagO2OYcTTk5E7GURAbBWDFilnYvq5YeAxIRzu6+woGgQVXpG5aWE
         JnWdA63i6RHVg8FziHbJ7oHagHPSrqQkICiEx9jORYON/d65H2GdXMu9fKGco0MdMt1E
         Jrk4meBp3rZJv7LtcfDEjthqIlvX593E3oVk9obDpKswjJ1MHZKz/6onxS2LGYtUy0S5
         qT4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uXYU/MRkYt3ZFgFmQVT9j3GIXeUXCPP4WaOyT4C4pHM=;
        b=DPY2bVwLs9+rylWjk0/wcB9AaqIH+cMiRDL5yZI8xPFBxUQsaCrIvrySDlM6kFrDqg
         qZvcITSbTgtO33oVwxas/KPgu3PfKXdDRyb2qi1IkbSVtvQJ5asfzftK3CTwZBrAMX+Y
         CQAFDkNqRmIcJq9rL67pfRyD5gNiJ9nTWKtCnCY6nj4p9rbzUesJu6mEFaN+pJKEAW8Y
         S/9XW5YxoZtDhu1SK0Dp4X8It0X/+/Vxyp9aYcbalYtXTiiOD89730PiYQjdoWabmQ5U
         0vcWUTYekyiHUDYmDmyzN3KFw/lOuBUIDYjgoCykXtVHHzPcGqaLLkXGfHgl8yfTYHuF
         VqTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310/V79OfHfhiKc7+/ADvqrV2W3wiG22IHcIDRhAOJlDOeCXL3Y
	B0X9EbCSH8UkKoddqpsKJns=
X-Google-Smtp-Source: ABdhPJyvhfzAS/Y5BFkW5dsUGyho/RtUCSU86Vm2JxSDMABKraZgC4B+Fd92umTR/ffgyXdYKD3fCQ==
X-Received: by 2002:a17:90b:1249:: with SMTP id gx9mr26431088pjb.146.1609693952341;
        Sun, 03 Jan 2021 09:12:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:548:: with SMTP id 66ls34908280plf.6.gmail; Sun, 03
 Jan 2021 09:12:31 -0800 (PST)
X-Received: by 2002:a17:90a:8c87:: with SMTP id b7mr26976204pjo.158.1609693951839;
        Sun, 03 Jan 2021 09:12:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609693951; cv=none;
        d=google.com; s=arc-20160816;
        b=WMatOcaseDcKVd5/muNEOPMil4i9UqKqhIlIpLTAXJTvy/YgDcj/OWZvRfEG51P9nL
         RLwcWFZVKdBm5ytHadtO+pWtHfYF5y7qSv7XzkirJI4UGoPOSxAiLd7dMLJ8ITwGByOm
         O93E6YqxGrG73sP2gR7IKoqzYgM+5dGXHjEiW1yMHSGW90zZL0nxcZlbuyKvzxgX3uwh
         XTnJ3gVG9L9TsvA0sR96DqLBdi33F3slL1UJu5X3hC+ncs26CO0zRW8Ql2cZMR5bhamv
         N0U1cxpVPOHXImbPvehqBH/SFeKkYfetfDslMJ5raz1Ola+mlaws8XhNN07vtz4xuMDI
         XXxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=P/GeiIxcJ64ZQ6SmObKp07RN0gB/xHVcCELrAtFy6J8=;
        b=TzQ18xZmA5Tpg3sLK/WMJiZoRyloy5OcEus6CZhmCweO2hL4Oqnci4114OOB/GMKNT
         Gpi7J/5KDCg4jG7uushkjJRVJBXkieMFGgP4rAN9lRWUcBrb4xOTYOhTRi7+uP7rzDgp
         yZFZ6u4XNWhH1WrX1rkD/Hybd5hR4jKKuM8G2A2Ih72YFyeb+4oiv7BeohLUUFkScOwu
         Yu5gEhtQ6oZWkkvA8dIrqqI8fvvNeZwg21ItwSzjRGe+syjS16/31ySUgwT0k2WeIG89
         aFfZPJsSS0Ji+q1p3w3K301vtCl+TX1/ba0Sl0ZPoNdhMp1IcKzyKnql29747OhCdEou
         Jc6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=j9nC8spD;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id r2si3456219pls.2.2021.01.03.09.12.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 09:12:31 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id q22so14889191pfk.12
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 09:12:31 -0800 (PST)
X-Received: by 2002:aa7:9619:0:b029:1ae:33b2:780f with SMTP id q25-20020aa796190000b02901ae33b2780fmr7380595pfg.26.1609693951614;
        Sun, 03 Jan 2021 09:12:31 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id y3sm19771657pjb.18.2021.01.03.09.12.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jan 2021 09:12:31 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Mon,  4 Jan 2021 01:11:34 +0800
Message-Id: <20210103171137.153834-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=j9nC8spD;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Acroding to how x86 ported it [1], they early allocated p4d and pgd,
but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
by not to populate the vmalloc area except for kimg address.

Test environment:
    4G and 8G Qemu virt, 
    39-bit VA + 4k PAGE_SIZE with 3-level page table,
    test by lib/test_kasan.ko and lib/test_kasan_module.ko

It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL,
but not test for HW_TAG(I have no proper device), thus keep
HW_TAG and KASAN_VMALLOC mutual exclusion until confirming
the functionality.


[1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>


Lecopzer Chen (3):
  arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
  arm64: kasan: abstract _text and _end to KERNEL_START/END
  arm64: Kconfig: support CONFIG_KASAN_VMALLOC

 arch/arm64/Kconfig         |  1 +
 arch/arm64/mm/kasan_init.c | 29 +++++++++++++++++++++--------
 2 files changed, 22 insertions(+), 8 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103171137.153834-1-lecopzer%40gmail.com.
