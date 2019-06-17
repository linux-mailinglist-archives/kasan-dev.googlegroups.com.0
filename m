Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB46ETXUAKGQESMAM5DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id EF9D047ED3
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 11:50:44 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id l184sf7405944pgd.18
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 02:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560765043; cv=pass;
        d=google.com; s=arc-20160816;
        b=NuZV4UjeYbAsKTA2JHE27F6jcQZpHX4CdAP+iQ29j2FNEWjbVWR0VUIERUX9dhETE3
         DbdIlWX6FtPGUQgRld0bHoFlnob81XrXg8mdlreGlMVM0LYyWnY7a6KvYdbYk+96EpJp
         wbrg0xqilDEAJvlDqDygMaCCt7OabRAV5v21ccSbSov23JUoujlM0e6qk6noCjH9bY3B
         vrY6Ox3Oi1l80HXqgjuXHF+6oLE5KbzJ7e+KeaHqb948PQSJCyZxJKvLxjaXYzg3ylm3
         FWCuEA5nk0apz1VqkaErBzQwPwH29f84897odzcJHLTjcsTwKHqBgwoTPiox6ckocFie
         cBuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=0zY23oeG+G6aTJ9O/7C7ahjhkptfx9rkaSFJ/wPAaR0=;
        b=pOfWC9b4t/hj8XS8WSgT7ypfI9p/nXZS+PLAo2GeTupWobjEWCtzlA4TWb70WiktKD
         CFd3hKlkkKO9OS5CotWV2vzsPXtTAzEfMQJro2sofXAUyHDLs5eSohtGY0iXkedDCXvw
         KpFhTeQa67ImXp9ru+uK8qaT3zncyK8jL2YashY7dTQ/Rd6gbSWara4R8IKp2UOzf9qi
         /+5oXRcZkCP9dKKl+dxKaVuXKp1T04cSXmtq9gGuqA2LryTcEqdAkytupfbLYiBp+v6x
         +4VkZ1qKqDGXaFV/pbePe8B6BcXdmyCFDr61ikh0XdhzP39Gnivn7QjrwD8NPCQ8OzN6
         lw6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ustUwJ1m;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:from:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0zY23oeG+G6aTJ9O/7C7ahjhkptfx9rkaSFJ/wPAaR0=;
        b=nI1HMfY1MIZpRT+ZOI3svLRd6TbKZGgDtqluCpvTACKSKqI8wgyCUVTM4JQcihWdAR
         vNQjZfahbuzUcUtjukhpx2Z1pXxxvIIRsVf3XPeDlRjS5LrsVN5u1NdIW4AiflU1M8hJ
         MLCkQEzaLZ0nACorEY55trlc7fg6ZYDLQ4eDgsTPk2u7MbLQmZrYtm84upSV2Mr+fy15
         fhAIZAR8DGyhWXNPWnaFNn0a0m/Lq0yhoCvhfcNIgv9zPSYUOzS7TX9QqcCMHNVQLYO7
         HJoI1WUh7IJ8GVmVP40XjSvdtL6hQS5UaHN/Fb63Am/piHxZYn/LiyaKqJ4EPi3kG5qq
         WQrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:from:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0zY23oeG+G6aTJ9O/7C7ahjhkptfx9rkaSFJ/wPAaR0=;
        b=SkcC3ko3Z89V36KlFhNfvWAgI7bdVpVAPOMxHHtDigIcNEKDsxjp7PQVMPNKFptrh/
         fOQtb3fLI8hIk5lDDeOXzRbUmQvf1yhT5Nuef5Klwx0GD5MPiwCr4UizZgGZzX7B1N1v
         +ZYgB1+5llZ0X8CS7gIiDexpHgQSMzx+p3hdv1D6saDpEeKBpPZNS/gp5E8vUmaPNl5M
         DD2kVHi5mPC50UqAfnPc1tCWS05wsAXgFF4fdF8yMyRZa/XLX8L9DvJNLyt6YvlR9Ryk
         ca48DslPmpFR5ff1Cfbns0uYmgThKyrri5XloRQgurlLwz0P2Mg2j0X/TuLAuRVKfYN+
         CCaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXfvs7+SZ5URE4yagXCz4DkokB9rkKwCz7T06qvtYobwIXdt6mP
	QtO7qkVJ71bDw0W7kd9WFqs=
X-Google-Smtp-Source: APXvYqxn4uazdZdmdPk+BeGpTXLVipvxUmsI/ogB32/274jcYAN/1pENXm+ZzmmR0u5fmGsJ/pjEFw==
X-Received: by 2002:a63:dc50:: with SMTP id f16mr32481739pgj.447.1560765043188;
        Mon, 17 Jun 2019 02:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2b0b:: with SMTP id r11ls3672918pgr.4.gmail; Mon, 17 Jun
 2019 02:50:42 -0700 (PDT)
X-Received: by 2002:a62:68c4:: with SMTP id d187mr115738891pfc.245.1560765042927;
        Mon, 17 Jun 2019 02:50:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560765042; cv=none;
        d=google.com; s=arc-20160816;
        b=BP/GYGaMblE4LUUTXi3+CZbklgGMYo42mdqM4qzNbVKWFeg29lLQ0vmdJlQDmVMDXb
         gE7G00f49Hx59e4Gez168AkbO36ZNoPO3psIys5+fcYABMV8byxECqdV6VNuKrEgNP3w
         ZOgi+zwXAc1nzW8MjnhMiCpMBXX0qMF/btAgoZMehtrFYt05TtvZ314MWzJddE7eMybI
         dvuKUurXt333i1O96hTcMd1F/iA7hzk6L3y1S0eT5BVEhjJDkWUTzqeAiW2Yk6EVJd+C
         2tl2ThjBfOb93jAadocaCkIBazvGsHLDL7/9ABzVT3exK1Didox/4Z56WJ2oGFHDfW6b
         4D0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=x1Yxlx8nxRTiJTX+M/7X9MTHCRDNvbOzxq7cKA9jw44=;
        b=td0wdEBey/7DwFyK64nFOAhUTnO/OprLc+jELznPqGt4r4aRQn2B8b1xJIRlrlVuoG
         jRrQMYnDNgU+N7CuWzgKWQyW4IggrO+b69EXsTssTF3NJUu7sCrAVodZNb4fMByiknEX
         a9TUAPj8ckqXDUGBad0/svsJoxwUZcj1Z7xlE59ZvfrPfs34YQdXbBi7Jfw4YfLV4XdK
         uDbCIykrhb8n6Mq3D76TRC5TtF+nEIJtJ+Ag5USpf7FUcq6SraTbkL1+ZfHDSBANlAF8
         D+fem7JMZ2r6ERsgoNa5vZl2OH2HoQobMUi76Sry+edHAcEbBEeszUV0JSbW+fZ99gT4
         RFOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ustUwJ1m;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s60si344939pjc.2.2019.06.17.02.50.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 02:50:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 342DB208E3;
	Mon, 17 Jun 2019 09:50:42 +0000 (UTC)
Subject: Patch "x86/kasan: Fix boot with 5-level paging and KASAN" has been added to the 5.1-stable tree
To: 20190614143149.2227-1-aryabinin@virtuozzo.com,aryabinin@virtuozzo.com,bp@alien8.de,dvyukov@google.com,glider@google.com,gregkh@linuxfoundation.org,hpa@zytor.com,kasan-dev@googlegroups.com,kirill@shutemov.name,tglx@linutronix.de
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Mon, 17 Jun 2019 11:50:40 +0200
Message-ID: <15607650405241@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ustUwJ1m;       spf=pass
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

to the 5.1-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch
and it can be found in the queue-5.1 subdirectory.

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
@@ -199,7 +199,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!pgtable_l5_enabled())
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }


Patches currently in stable-queue which might be from aryabinin@virtuozzo.com are

queue-5.1/x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15607650405241%40kroah.com.
For more options, visit https://groups.google.com/d/optout.
