Return-Path: <kasan-dev+bncBC5L5P75YUERBY67R3UAKGQEAICB7FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 574C8460CC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2019 16:32:04 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id d22sf711274lja.20
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2019 07:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560522724; cv=pass;
        d=google.com; s=arc-20160816;
        b=DSpgremnA51eINRrCNn3BebvlYj2YEqF1YWPuTPf9fCCqU2kd2uXWq0ZVmM+BbYPXZ
         5U6jRKtC8JK9ZuBYfcXMpAGqiBw1iiFfjxD4ofaL5W4YnhkvGf9FZ6c3OxbtKogJKl5O
         nbie36kzoZjU0eRMRPgpUT4A3ctgYrj9W+Xi3RoKTadxmxCm0unkLikgYlAeiWGTdwos
         kwDbtGJmofDhR5xgMl360jRGlwiQPrawG3QikeEw+wBj9e+tmvs7ydpV9RBEo3UrjyPk
         Pp9IAy1Lec+QmU/KLbk9Su14T0K0Rfv2fnaqKZaZsNfIvaHOQqGrZA6MyOmqafWFQ/wi
         JtmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GDodIfoThhCnvL91FrCR8c0jFhGiR/C/EFXYiG4gyGw=;
        b=AD6M5GZ1ZyKPuGlaLpDE2h7l3KNgxm1MNAmK4Vjv+1TiO9PPfp6gbYMlkmYLNdx5DI
         f0Qi8AuuUypAH4ofKMsgGGY2hVK+ftYV94vwmYdPM36QxliYyTAIbmSnIaQ5ymu/tSeD
         d8nwJQS9Y+qG2Dx2YBxXONaTZO8g7EPHdtQtqL8PPULxA6juG79eZJnZxJmxhhxpXq5U
         8mWlienGrEC56qRb0bfW2aqvUsMhTDIof8nwRl3SYbAIDJzrccvsXm7G1ZYTb3F65RbN
         MfSwSbAof93g7yW8q3Wp2Uaq4YScFnx5+nxjCrnj9pQB54t3wxmu8lodYaKAGi7/Q7l7
         xOeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GDodIfoThhCnvL91FrCR8c0jFhGiR/C/EFXYiG4gyGw=;
        b=jhaCDtEpavcr0cg41Ku8Lwh3UKau17uHd+goEHrZTRzGwOHr/KlhhfL21SxBFqp+pv
         Xt2sQfhYLq6mXs4HrKqqSDIrQUG11kOt9GhEN2FaRT3BZJrALDYVMOKxJ0TivxCqxgca
         tg5eyFjyxoxra7e5PH8LW8AKqlm4j+XC58NB8qX09zha3aiehFpYSdoiBVCQ3ZJlhuNd
         i3ZFY/vB2vI088tVTIeKYuRDnxdmp3uPihb3LLVakfItIwzih0Gj+5sBbDjhDMDYYbKT
         Ac+EeklE4UsHB+za2un23X+VCAMUMdEi7FYh32Q54f8NQNu26g2RraKCuOW5Veqq+lDe
         I7sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GDodIfoThhCnvL91FrCR8c0jFhGiR/C/EFXYiG4gyGw=;
        b=lePX1Fpt50ntBlQ1LV8CynCg/DjIPE0qvhhb58BDiw+AThH28ezBIDiRVko/GpTHU2
         c0YMmNy5dJD4QoBqxun9t3ppJWNJu0HK0ZGJRc62iVWQQEjGEw4+a2Y6FYjIn4qxSk+z
         6EMndvtFJOmwfu19ETXVFUbdysqL15N+uppc36S3dltlUeeY06sKikoXof5eF0cC7QP6
         +HGEz1mmmR1mW4fU9J1T82nt7PLQwGCk1P/GHI+PRCeelWjjQV+tHrU2Mqqvp/p+n6UG
         roH8kg5AwUmBCvW+4fBuNw4JEq96CybeMAIuRe9vL3jVlQk6isj1HoXJTKwxvpbGHlpV
         j9Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXhmfcKtkTWBLpNJaun97PC+KiO/KpRtO0tWFTakDAjB3jVR76V
	vjOtx70Vbu2HgjhXajrATMg=
X-Google-Smtp-Source: APXvYqzs1mNaLm2dgMScWR+dqVgJw06J6Vj1vPVRYYGwCLgrqgDLWq+bZa+1VT+vUrYqaUvEfmHqSw==
X-Received: by 2002:a19:490d:: with SMTP id w13mr22663749lfa.58.1560522723942;
        Fri, 14 Jun 2019 07:32:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4212:: with SMTP id y18ls694171lfh.4.gmail; Fri, 14 Jun
 2019 07:32:03 -0700 (PDT)
X-Received: by 2002:ac2:4565:: with SMTP id k5mr44650618lfm.170.1560522723503;
        Fri, 14 Jun 2019 07:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560522723; cv=none;
        d=google.com; s=arc-20160816;
        b=yOVld17sC7Au89LJuABYUSG6qHFxGzmAOvwN8/rGGZHRRAHxNDVprpwkHbJP7xl/1z
         gp7g5ODmNlkQAya+AuZtStEA5hm6i+c1lhDi7Xob7S/6FKkTeB+ugDFShNpE4zqWrQpG
         7N/4AW0iQsPaQyTfxAL+Bbahdh7KDjMlO9kNURHUG0c1MCUkKV1M+i5CJM+LWvh4vAK0
         dlhdRWxioh0Q7oz74eOUxoDN/u4C/f08QEGIjOkvmZ+Jiw3+5d6Cvd5imlwdOco4Ybjl
         LCUjZHyWSAWIZMb66WM441wjuWMazRNrbO7iGpEbF4sOmPa4LID4+9zY+Lv8L1A75sG1
         L6pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wbLJHPMjxWp+B1iAx3Cp/2u31haRFK/GryuhagDKsMo=;
        b=gVP1ze1toHSfxmAKPAzpe4Z/kDdyffxJMnZGukan9ADo5A4daWHyZDyaecq40n8tOt
         HPaMrUl5vezhyZFkpJ17s6g9LASNuM6HfCdrGLhcbx3qszvjpUa8oglKG0ga7qf061jp
         Twvs+4qyaFpHHyoCXEPzp6Twdt1gUvpfYHxEQIVE/NvWzAnbi/Q34sfyouXdHH0m6rfy
         lraOqCgYUwzgTwvcFn5CzhSPjnaoVL8XF5d3PEQWUleRz8hrSlkfUGNAzPtg9EMkLxYq
         3ijSReYSLGlYWugqgxx1Nga7TpkIjnRpLo1K64HEPWcEYk/bNq8EJlJqQbYb7ObIS+pX
         jQDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id l3si121701lfh.4.2019.06.14.07.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Jun 2019 07:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12] (helo=i7.sw.ru)
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbnEw-0006yb-Sg; Fri, 14 Jun 2019 17:31:39 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
To: Ingo Molnar <mingo@redhat.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Kirill A . Shutemov" <kirill@shutemov.name>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	stable@vger.kernel.org
Subject: [PATCH] x86/kasan: Fix boot with 5-level paging and KASAN
Date: Fri, 14 Jun 2019 17:31:49 +0300
Message-Id: <20190614143149.2227-1-aryabinin@virtuozzo.com>
X-Mailer: git-send-email 2.21.0
In-Reply-To: <20190612014526.jtklrc3okejm3e4t@box>
References: <20190612014526.jtklrc3okejm3e4t@box>
MIME-Version: 1.0
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

Since commit d52888aa2753 ("x86/mm: Move LDT remap out of KASLR region on
5-level paging") kernel doesn't boot with KASAN on 5-level paging machines.
The bug is actually in early_p4d_offset() and introduced by commit
12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")

early_p4d_offset() tries to convert pgd_val(*pgd) value to physical
address. This doesn't make sense because pgd_val() already contains
physical address.

It did work prior to commit d52888aa2753 because the result of
"__pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK" was the same as
"pgd_val(*pgd) & PTE_PFN_MASK". __pa_nodebug() just set some high bit
which were masked out by applying PTE_PFN_MASK.

After the change of the PAGE_OFFSET offset in commit d52888aa2753
__pa_nodebug(pgd_val(*pgd)) started to return value with more high bits
set and PTE_PFN_MASK wasn't enough to mask out all of them. So we've got
wrong not even canonical address and crash on the attempt to dereference it.

Fixes: 12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")
Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: <stable@vger.kernel.org>
---
 arch/x86/mm/kasan_init_64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 8dc0fc0b1382..296da58f3013 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -199,7 +199,7 @@ static inline p4d_t *early_p4d_offset(pgd_t *pgd, unsigned long addr)
 	if (!pgtable_l5_enabled())
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190614143149.2227-1-aryabinin%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
