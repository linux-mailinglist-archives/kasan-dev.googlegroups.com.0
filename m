Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBYWETXUAKGQEIIMN3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 03BA947ED0
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 11:50:27 +0200 (CEST)
Received: by mail-yw1-xc3d.google.com with SMTP id b129sf11650852ywe.22
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 02:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560765026; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypzK1yfnJURyHfokPtXm3xIjGXfC7UEAC3kcK7S/FiiziL7KR+OTbCrZ1Jrd0dDrkY
         Q8BosBBedhQOWwaA9Uu5i2M3iIYrZACL32LskIHe0eZ2VsZvDMrpKCiAbwoP2N43rbRQ
         nwy1cHTLzu2jaTsjjPSvvIEAuV4Pa7Q8n1bjM1Fr4F2HRSVWXdRbmYdY+QnuTox2GX4P
         H6ZjE4Eu5U+1AQVOp/nx9A4ytJrcB4uWfPGGviLZ1S5KYcOZpNghameQ+KNVzDesTX5W
         hgH7UYSiyEB0p9/2+gWu29aJLtVy6G4/SixvVs95wFbDFaj3pj/8hEKnJX5DniZBQyvK
         vXig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=JTlcOfLXrXEhWtc1Iuj3sT79uITnQj9DU1QKEqZqoso=;
        b=D0lw8lPUry41W4DHP1P7vCI20pzT9Vy982Nuuh0SwwbYwTBS0uWXGGx8/OGl1A8aVC
         RZeiC4T2U1PiQRR2xvuM8Qqv6IFsmQPZNssvJ6yM9gnW7QXLNV0wOdm1G9b0fkrY2NvR
         BjGPAGEEqKxlRaVWLjSsoa5xnUViEjAvGzJkpjYyz5sWfKK/ZyhGYuCdpbq+tVnI1nbb
         lOMs+vVAYwKzmwmsm/7nScJbg8VE4L0hxvwJ3fVFrqNFwDk1un6efNeGZaP4kNDQE+Ri
         Mp8vDtuLOAyLsVss74lz+CVpZolQk5yCc6OKWDYdKFDWdFDPwcMjVv5k9mG2DC4YTgeS
         AJnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZAfhPJAT;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:from:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JTlcOfLXrXEhWtc1Iuj3sT79uITnQj9DU1QKEqZqoso=;
        b=rQUj14Q4KF5LDvdfzi6tGOlMzwX6ei5HfznSPImGNsDCfJfrclxg90GIHTVm61ohdY
         C3mtVwKekNgxXl1MRHPqfhSDa1fzEOE9hWCfamOek5ZIHk5b6ExZRxkagpMtxLJGLpmk
         h/hgB3Ml4eFwn0b4FwPW3qsYc4Lqo4om5MS7jR51RhTl4HcCLyMqx3FNOrLKrc7KQjnZ
         eJXlodzgksYDgffeErEk3ebLsAvUq/UsgP05Nzq83yDK/90ckZD63Wn51ch1xRwDAR3G
         Hnt+ry1wDv3iA/2YNfxiOpZ5sJLuIpoO6f0bkHZPghvFAEmuf3aa8r3wvC72+WWeuhtt
         kv9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:from:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JTlcOfLXrXEhWtc1Iuj3sT79uITnQj9DU1QKEqZqoso=;
        b=Hy9JPrpYrWx6pKuQKgCZ/vcFMvXo1g0XYhI18DkSOjrKBHpk8I6IMXIgzMSGlv04Rr
         EpmqYY4D1Fv5jcqMqDYXdjAEahPPiPCq0m9VsstfhLcKpiXsPDzBDKYhcA5Osyn3NArj
         iO/jPno1GphY1610PytFSekLN257HmWHj1jGzx0LtfhzZ/ZJIGIU3KxjF4OSmx982795
         E6WgqiM+2fxr+vOI0b77JTJhU3fxXnBfdgVAU/DvJvQ6ED04W95xadLNv6I1MwOvwOwK
         381uu1XFhyBYnN37ZnBbepMJxiJJgpCvye5/DMsiiakKvHSSxyKnEV/2Mi2gKcf3cnPl
         1zXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVwMasMwJVPDurdo1rOVKV1NsIN0mVFAo9NDa798Bk6PUMZRpQW
	FdAn//0ttcmmTo5cN9Hfjv8=
X-Google-Smtp-Source: APXvYqw43C5J5aHXmnjnGO1X7+NqI3xoqoOYfVLIqevQGXol1IhuABf3S9sIiM/seyg1IOgHr+ANJA==
X-Received: by 2002:a5b:9c6:: with SMTP id y6mr8388151ybq.500.1560765026084;
        Mon, 17 Jun 2019 02:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:238c:: with SMTP id j134ls2242460ywj.0.gmail; Mon, 17
 Jun 2019 02:50:25 -0700 (PDT)
X-Received: by 2002:a81:e604:: with SMTP id u4mr61430737ywl.373.1560765025840;
        Mon, 17 Jun 2019 02:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560765025; cv=none;
        d=google.com; s=arc-20160816;
        b=kau1d8uiPmOUNOs0kgAPzN7uKJ9eXBKDfoKOuA+XDd5tT5xRkg+gFk9MiC0V1c04J4
         q6Zpfnpq5MbYhaSFCApDxIMgTMExXv4EyIO5G8fBxPmQBZxRsZTdtWRBFQnnrZeSAI63
         eSFMc4Jxb2lAUv20M6ctorkGuwj74sI7SMLFYlx3tf1b8ygDRCJznw2hTbAQ6uYrMHm4
         yseGe2pzjJ1ncITwLX5E4FylLz37cGBDcY/xZqPuBSlbM0hqubbLglNL+UYajLTTzQwN
         50vsEv90lqqGjEDNyUSZnrbcmwytQE6SM2oQOACsMqoaHo3Th27LhzlYiyiCnZmKaO4K
         FvHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=elGFJFhQ5+e86I5119T2w+w8QTg6I2vvZu1vyXxIVWs=;
        b=LkCAhncIgsClifhhJaIHtKu5nUG3y5HLyC0cfs4dQhPE27Qr2uNDIxxcEw69uavep/
         DEb5mbCbMcfuFV1TzvBQ5xZYj6fM0NbSptwLLINJyfOAnyrxKJlBYctjX8XwZAdVcZKq
         NDP/40qGoev3b1c+Hj9aEdTIgs9XNHeeZfEyERZTY9mg1P58TG3ByT9J4VKp6YMcgpm2
         dMB0GAeEVOL84xoT3j8+MKKerpBNbV3rEmW+uaVe00os/9xUDxXL/ma0NH3VQtsnkjDr
         B/FL/FnxpYuqX5GEsfl1jh/ZjEL92s+/BNcquxsXL1MSbs+72ldg7wOZ8CzbjA6uNwkm
         udBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZAfhPJAT;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o62si581097yba.0.2019.06.17.02.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 02:50:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4A7972087F;
	Mon, 17 Jun 2019 09:50:24 +0000 (UTC)
Subject: Patch "x86/kasan: Fix boot with 5-level paging and KASAN" has been added to the 4.19-stable tree
To: 20190614143149.2227-1-aryabinin@virtuozzo.com,aryabinin@virtuozzo.com,bp@alien8.de,dvyukov@google.com,glider@google.com,gregkh@linuxfoundation.org,hpa@zytor.com,kasan-dev@googlegroups.com,kirill@shutemov.name,tglx@linutronix.de
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Mon, 17 Jun 2019 11:50:22 +0200
Message-ID: <15607650223187@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ZAfhPJAT;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    x86/kasan: Fix boot with 5-level paging and KASAN

to the 4.19-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch
and it can be found in the queue-4.19 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From f3176ec9420de0c385023afa3e4970129444ac2f Mon Sep 17 00:00:00 2001
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Fri, 14 Jun 2019 17:31:49 +0300
Subject: x86/kasan: Fix boot with 5-level paging and KASAN

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

commit f3176ec9420de0c385023afa3e4970129444ac2f upstream.

Since commit d52888aa2753 ("x86/mm: Move LDT remap out of KASLR region on
5-level paging") kernel doesn't boot with KASAN on 5-level paging machines.
The bug is actually in early_p4d_offset() and introduced by commit
12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")

early_p4d_offset() tries to convert pgd_val(*pgd) value to a physical
address. This doesn't make sense because pgd_val() already contains the
physical address.

It did work prior to commit d52888aa2753 because the result of
"__pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK" was the same as "pgd_val(*pgd)
& PTE_PFN_MASK". __pa_nodebug() just set some high bits which were masked
out by applying PTE_PFN_MASK.

After the change of the PAGE_OFFSET offset in commit d52888aa2753
__pa_nodebug(pgd_val(*pgd)) started to return a value with more high bits
set and PTE_PFN_MASK wasn't enough to mask out all of them. So it returns a
wrong not even canonical address and crashes on the attempt to dereference
it.

Switch back to pgd_val() & PTE_PFN_MASK to cure the issue.

Fixes: 12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")
Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
Cc: Borislav Petkov <bp@alien8.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: stable@vger.kernel.org
Cc: <stable@vger.kernel.org>
Link: https://lkml.kernel.org/r/20190614143149.2227-1-aryabinin@virtuozzo.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

---
 arch/x86/mm/kasan_init_64.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -198,7 +198,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!pgtable_l5_enabled())
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }


Patches currently in stable-queue which might be from aryabinin@virtuozzo.com are

queue-4.19/x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15607650223187%40kroah.com.
For more options, visit https://groups.google.com/d/optout.
