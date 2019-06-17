Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBVEMUDUAKGQEMVWZHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF1A94934E
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 23:29:57 +0200 (CEST)
Received: by mail-yw1-xc3a.google.com with SMTP id j68sf13604203ywj.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 14:29:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560806996; cv=pass;
        d=google.com; s=arc-20160816;
        b=xRKPMbXRMfk+005vtuphIZTgBlBl2HmfVACRuaDCfdT1qS6Epf30Wjpk85tVeyaSej
         CGrcMLp2tSb06kpCT/6LPyspPHdw4BpRrB8npaoA3g3dVhsz0/qGGrFsNt46+tco4PVX
         hQIF7fBWAPjzuUGny7O9p2Pl14UPObXtb00rxDX2rjID7atrQj2eaRVQV/i/+DRHS3Q8
         Taywo25u8e+YR7PSE2qwcQ/ElEljRiRyMc7T1hKUN1oKRwPk6S1MddUcAIA7JA6hz9oa
         RqjhAa714djaA7mIpyHcWljdRYd4XPzlEdMUWXgwQkvlAipxAv40abH+uCmu95xyxrdW
         riYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=xcO1ez+jDYGrIgRGtZKuAB1NZu22RNqKXdar0K9lTgI=;
        b=YyzlnZ6IfOUByEkpCVf+ulzwPse8BwPRMo9X9KySY6v1WouQ540lXAFTL6NSU6xbqe
         9TfpT4iks2uKOfZ9Zy5o8EsN92TB1/kP9kJvLQX46zf0qVaeuEyEZsmLzYjOPxqwCqmU
         DRtvu7K6SeumQfnLBBxP+bV1DbVoE92QPxwZni/W4shguK/NhcRl559mVOIWNu8CNrZf
         PTRaQiqiUZySVps9OcBzeAnQHD4qDIeFZk/CGbymSr+Q33H/C23VxF+dVQQZpT5nzMmh
         qCdp6xGAaRJXG8eZXAiky91/MdAnP5Vi21E0N81T/y6XMV8/kOPRSic5CaXJ1JRJFJlp
         JMhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=L4E8Pvzg;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xcO1ez+jDYGrIgRGtZKuAB1NZu22RNqKXdar0K9lTgI=;
        b=pU2IGehqvOuPMAsIcm4xd8lUPa/2H+iMVy8QgMi1HSxUGEBCq+WN5rR7r+R9/TnQAU
         +qXuJvgen2PQgnHjpPpQjCcRhAcveHX/adunyVO4oMH41WiPWYSV3+PhwAMWy+wWUV31
         AbohK0fz+zaLHV+ayq7JBjqKLRjOt8CapdTHmVYcFOtpicW8wcP24xth4Pm8csLBxyaG
         Bk+4wYDUL14XdWJgulngUGik+Ph6kVMvoK6leHkF1roumr7vbUvWE5VD16zJcdAaeujo
         kq4VEEugi/tgju/VfnKcQ/LzmQRhgoGTXFifqX/fyCX/4UA2vajX0Dp4foNSFBrWdZ/l
         MsIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xcO1ez+jDYGrIgRGtZKuAB1NZu22RNqKXdar0K9lTgI=;
        b=XAb0JLFTyeyxPdfhQjh3+H6R7KlWACtqkG/qDJBfCuW8492EcGE/E7Snk0MwZG3eBJ
         CB+HizUTUUdazLp68Byrj7dmVKJrDpKpQ9uQ9RROuIzrj1/z0xM/KBXpCjIYI6tGa1fp
         N1J5FxkZlCrl1ooRDO8JpfGUMPwMnPHInzMY7ei6XlWTyys6HYoExeGyI8r7jzoOUMxx
         yhGonvJVd0dju9RhNGPspl/8hYG2DJgW4pYKEclTrizFn450ImYTv5sdIwL1LGN4qVVZ
         969rjJ6Us30ZR8TUEb0bpPlZ+DmJkHj0u1anKgh/TNA+Sz6If3l3JgWo6KRt59mV/hDt
         FJNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWeGzx85Pknf4B54DHkP9oT3gCC+xqJaZIxv98xz88gFOIMrD+b
	ATzIP8QYUqkxJOGqmEnUMl4=
X-Google-Smtp-Source: APXvYqx2einrpvu6INgL9V6wGoY39qPHZNrT20N+VKjHUhh6Q1HCTuISfXxiQ5k4qzwPqeUI13Jtuw==
X-Received: by 2002:a81:2703:: with SMTP id n3mr55065402ywn.53.1560806996628;
        Mon, 17 Jun 2019 14:29:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9a0f:: with SMTP id r15ls707802ywg.6.gmail; Mon, 17 Jun
 2019 14:29:56 -0700 (PDT)
X-Received: by 2002:a81:270c:: with SMTP id n12mr54557666ywn.134.1560806996328;
        Mon, 17 Jun 2019 14:29:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560806996; cv=none;
        d=google.com; s=arc-20160816;
        b=pp13aQHQGHrQ8QQjU4MDSe4FyCMDiRBLi6JyGnDqNqVMqhl1Gmq+d3unnUjX5cTM2b
         UhFwnKjcanKOELUYL3p/qPw2FaheanQD6ot3VEoxLH7L3sR8Sw4bgXNRhOuhIYBL538o
         DSJYdUrhGCEya8Xr4RvP3jA1bmRFoDpdWJOFZXtLiMNPu0e3rIElBy0/DIol4JoT9tA6
         yEeDaerR6AvcPvam9KBv9nXBeSHX2KT8/EP3ueyHOwgDSq81sf+SRdLvrOaUoqQXbS10
         pH8aB0TMRzFpGhUZwxkacWNVHsmQQg7Fs3ZH1wgumeGFTTT969mzzgs/deF4rf8I0cK+
         eJhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=OYlmn6i/tTq9vQl1bT/O00OooK9W+BrgDeaXDD8l6xQ=;
        b=ChwLgkM1RlbJ1OYTaCUA9ewFJAz62FUUdLcZOpUhPT7VE9NoDV7uP3xeIU1dZFdCuA
         K9ZtFUj0+hUxy631TO6XuJPYdIwWW3Aq9SVT0M/rB1+hOP1IeTr6sZVsrkirdWQXjC70
         OYBjICDaVfqlMDmjpJP9xQj76ViyU2TNocUteSN788vlK6ZjIf7ZnLD9PcopuTaLyM5C
         hLls8WK9YkZHaPCHGkADLSbib/pZrA6lOL8Lf/+ny7clQjGSuzBSS7frne3VFz7przQa
         hwpI/l/Ohdc3YDf2RTmX2qNB6cj2IwQ43YJQCu85qL3dMO105PhpXD0rUChKHRtKzh14
         IagA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=L4E8Pvzg;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p19si564030ywg.2.2019.06.17.14.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 14:29:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F2484204FD;
	Mon, 17 Jun 2019 21:29:54 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	"Kirill A. Shutemov" <kirill@shutemov.name>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH 4.14 52/53] x86/kasan: Fix boot with 5-level paging and KASAN
Date: Mon, 17 Jun 2019 23:10:35 +0200
Message-Id: <20190617210752.642577447@linuxfoundation.org>
X-Mailer: git-send-email 2.22.0
In-Reply-To: <20190617210745.104187490@linuxfoundation.org>
References: <20190617210745.104187490@linuxfoundation.org>
User-Agent: quilt/0.66
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=L4E8Pvzg;       spf=pass
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
@@ -194,7 +194,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!IS_ENABLED(CONFIG_X86_5LEVEL))
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617210752.642577447%40linuxfoundation.org.
For more options, visit https://groups.google.com/d/optout.
