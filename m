Return-Path: <kasan-dev+bncBCRKNY4WZECBBG44Y2BAMGQE3JDX7TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1EB33E8B8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 06:05:32 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id m189sf7990442oib.20
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 22:05:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615957531; cv=pass;
        d=google.com; s=arc-20160816;
        b=MLtLDtwoyBN5UnuSwTmQvGp9k5zAEcK2K1WlffhJfknesj+cPMdI/6yyqbPGS7TChb
         to128btxZ1aBVd5hLIQSiuIGoQU5BmlevZbAzIyD5EhH806FjV2yOHv2oqOLRqHYSLuS
         g2QMTQkKrAz+hgmc4neupIGns/qveLeagb4fz5vUUFNQpHjBNd4ucT2Qql6YK4wdYv/D
         5AsPOSdwAlrMQcRGg7h255fFa0xFOTHwnDIYAZzlPsH5Kb6UzKj2LXHI52ZibzMJ8cNK
         jQKpCsxZowkoitGpN9GQj8Y5SihXAR3dxvJ6Gv49hPKPC0Tgta50dUD7wHoGFXWyukTe
         K0og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:cc:mime-version:message-id
         :date:subject:sender:dkim-signature;
        bh=Y8jrGVbvZrLrArctWZWQNHOruGfJ46a0luwIZn90+nY=;
        b=wCBVXfaCPXhQRdJOJdHvgy0w3Ev1SfWAdAMVzY59yDTSb8GCbyK4gll/l9Z45I1kWC
         IQxua/aTn3D8ZvDWkyFyZX0JDSWECy5AXLOyZws8EHwT8lQuekhh80dpTXlLkKk5tJqQ
         gJeUSvctpdoBDgkayVPUJg5/V7aNJ99f3iF163oOloaiRi0YRDrHGCnk9uBH5Wiot5Om
         VlxRFTmq7izmeXHtQAlipY2XvadRaZjAzCpKAQ7HvDBRBPAU4U8lJJguZ2wcRfHd9pMj
         as86I7kBWW4EUeEf4Mv3QDf2try5pXB5H7syreuCWxlji6lH3HjguG7N+V5mQTwxxDg/
         3TNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=MGlPr2zN;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:date:message-id:mime-version:cc:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y8jrGVbvZrLrArctWZWQNHOruGfJ46a0luwIZn90+nY=;
        b=GB3TP4Vqu7LKCHshPv6rfxtot8LP/RDDCAkBpEPPoYnMYLLCquQt5vcWDXB1Lmmhz8
         amQvCM8lnXg6Lithy9cgq46qUox0323Ubor/SejoT8lc6KninlnWz136TQ4/mh+bpECO
         ze4hwobBuJacXtbfOwDntT+yFYdnLz/xF3LWefcWXA7QEJm08bcOAeUXwJyMzf06FSPt
         mJejf6eK1Aa80zHXN/sdVq1+WtUkzXs91uKe0ziO88fVMMP05COotRMrZ0X8GUWnwBs8
         FkUnWDL5+San5PYoanG6eejwWswY9rcW/bQUpT4lPEuDlzok0NXnCnKDWpbl+54zFOV7
         13LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:date:message-id:mime-version:cc
         :from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y8jrGVbvZrLrArctWZWQNHOruGfJ46a0luwIZn90+nY=;
        b=jRwL3r4jKjqVhbppFIB8I/mvwtXGWPKYsoCmzMevq5+NvTjQe95dZ0UWEDVZCIwY2s
         3rUhD3HN+ABTMz5m6Id4bJII4hEZgW6oDZfAu+SFczLNoJ62utcZgd/LF0wctfJ/BpKh
         9b6vqHPKWMyOvz+VAtgvFYZ600piEJ9M/aJKbj5Zf8m2eypRivpG0GLKDFG4GnjAQspg
         Ec/QeLKcrVpcva9J2h0OQlHWMH4ZLCg6bB5NGxG++JY+43ThUuymYcrylejObg0sjC/Q
         Q1m2HXKBvx32WB4lq10wnQgQqdWN5fES4+psgf2CORE0mDgDNSKcRZgCcthLMbEDlEfU
         VWsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZCaBHRFSQqjPRfw4wHI/2+TUZUqHNCh8Mw4vqNPjuVDZUW0H0
	0wwSXtPfsY3nU8oRHcpc5mU=
X-Google-Smtp-Source: ABdhPJxMDTYXhPvH+WHMNVSiiAz5XcWxAr3JdNkBrqdgbZXoYTEILNod8GOIEdywcGKTPPHYPSL0Sw==
X-Received: by 2002:aca:75c6:: with SMTP id q189mr1539276oic.29.1615957531136;
        Tue, 16 Mar 2021 22:05:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:65cf:: with SMTP id z15ls5691975oth.10.gmail; Tue, 16
 Mar 2021 22:05:30 -0700 (PDT)
X-Received: by 2002:a05:6830:22f4:: with SMTP id t20mr1896937otc.45.1615957530739;
        Tue, 16 Mar 2021 22:05:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615957530; cv=none;
        d=google.com; s=arc-20160816;
        b=I4F1chBBscv4yBq21AnfPxvG2vtFj22398jkoGNpr8aI3V1flLu8ZucXdPzV5hr8/F
         PRyEvWY9EyxSkwD5d3RC/wU5eKFd1o1aoINJfyejdF7+7f7+cuwuHlLe802D1j0d5B6m
         70d/+WJ64RSyZSZvy4kQ38YdklVB/wv9GnUYHtTxoFDs0ORtGWQQ0cQU0qAECzC55Mrh
         TUmdWuiauWw1QrUBjA+SnXI7/rUComvpAqcma02bJKFHYv0pnzIrlHdpTxx0h/06aGiH
         JeBjTvV9v9UEvDtAgNBYiMPP4ctfl3lfM9GOu1rcy5xDdXNkhMC2A7iWVAvNnOLx9BkX
         pOmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:cc:content-transfer-encoding:mime-version:message-id:date
         :subject:dkim-signature;
        bh=74MWaAFPWeZRrJY/C5d35d6IGwQth/42igzA+G1JWys=;
        b=F8s9HU30Cul0yjC9UXNmlI7D0mtN1hW8z5OocjGpiB76zNIihLftzO1prL/LLUFpCi
         B8D0z4MShuGhXxe4VTHae9lfYvh26Mu1E0LhFVeB3+gON2HXXR69UEI1HmFmC5Y7dUpt
         dHqVI3tglpJzgfksnv8UHgtSdlKO6H3jd+BFkB9bttALmwMZ/RfCWR57DCHniiJ1rv9I
         XOiLrKtz57QhfTEruWFe+BjDwFqPsmbZ3c90RNbFQFwX2CoYZytlDr0sPzweHtvtcEFr
         dUntiWyHHsDLc4i4tOlHBJBohEIuoihq9VQzY38eCh+QRiG/vGW99emK0Ml8nOyDgbww
         8ulQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=MGlPr2zN;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id h5si1495615otk.1.2021.03.16.22.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 22:05:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id o16so7097174pgu.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 22:05:30 -0700 (PDT)
X-Received: by 2002:a05:6a00:b86:b029:207:8ac9:85de with SMTP id g6-20020a056a000b86b02902078ac985demr2671100pfj.66.1615957530001;
        Tue, 16 Mar 2021 22:05:30 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id d14sm1031270pji.22.2021.03.16.22.05.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 22:05:29 -0700 (PDT)
Subject: [PATCH] RISC-V: kasan: Declare kasan_shallow_populate() static
Date: Tue, 16 Mar 2021 22:02:48 -0700
Message-Id: <20210317050247.411628-1-palmer@dabbelt.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
MIME-Version: 1.0
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
  aou@eecs.berkeley.edu, kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kernel-team@android.com, Palmer Dabbelt <palmerdabbelt@google.com>,
  kernel test robot <lkp@intel.com>, stable@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: linux-riscv@lists.infradead.org
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=MGlPr2zN;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

From: Palmer Dabbelt <palmerdabbelt@google.com>

Without this I get a missing prototype warning.

Reported-by: kernel test robot <lkp@intel.com>
Fixes: e178d670f251 ("riscv/kasan: add KASAN_VMALLOC support")
Cc: stable@vger.kernel.org
Signed-off-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 5c35e0f71e88..4f85c6d0ddf8 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -155,7 +155,7 @@ static void __init kasan_populate(void *start, void *end)
 	memset(start, KASAN_SHADOW_INIT, end - start);
 }
 
-void __init kasan_shallow_populate(void *start, void *end)
+static void __init kasan_shallow_populate(void *start, void *end)
 {
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210317050247.411628-1-palmer%40dabbelt.com.
