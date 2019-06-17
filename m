Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBMELUDUAKGQEJS5G3PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BDF04930C
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 23:27:13 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g30sf10475176qtm.17
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 14:27:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560806832; cv=pass;
        d=google.com; s=arc-20160816;
        b=NRQN7c4QFnYjqXyuwjUwaNNx0q5DJ12/wR/Mb8LNnL1ubTIS/jTf/P3SESfZFbjkEF
         dpnk0W9N6q8y2Dk+bDuO/vf/2BZhAbQjJCQkyg+iHfgGiCSbwkG4P8wab62zorTB/bN7
         y9OB7nKYh/86HWTBDmKtzjCGHMMY0164Ti7k5p0OSDh+WrFn5djbZv9+NKuHLtd5y7BI
         TakFRnh+ttYkuq+Dk/essazbtk1Q+uaUI6IonnjxXZXilX/QYJWyyey854Eh6VmkHYOA
         ehISmtAH2Nl4C+TfTKRuyCD0LGqfksfDz5hY73Z6y/83SFuh2whkf06qnAzQZ08cfaHT
         fSVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=Fd8wEs+i15hpkNHpuReQi7S2sUWplSYq6WJQupzHG5w=;
        b=Z5P7g0UsjURlipVFl9w9MQCcwEgu1q19UOF9NwDBfLtQhXXMmmNCQD/rgCr6qzjaBd
         5C87ZzUpqY+GgXacZkSpRCQZo9BcJCbasJbvlkMlaiTxcdUJz/1mzCVsj8dd5rNR7Ng3
         BoaStT8ZtvHL0BU51N9QrlNf9WiDKgYoNw4kAKWqQDPQnCL6UfyKZ7jabDC9VNF/1icl
         Dj4twoTr9uHj3Cb4TFBis4u5PGUYcC4+wSUvOzyGp2IBjwIkMFcWMxAvsuU8Pmjw3mMU
         MEdHuOqz2a8jTe2tK2glK+1ItYf3yrYzaFF5NdyPpjEA9grCJRqmM5VU2UvxkjcdC/qT
         0WSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=uQoY7v5M;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fd8wEs+i15hpkNHpuReQi7S2sUWplSYq6WJQupzHG5w=;
        b=YY1O2z/Ekt+tkopmY/ITsB5MAeU+groEHlRqGSwddIwt5L/DmFUpylwVZSxIi+9Q9C
         Prdd9lx9iUtdZQOeMJIdNRva9vp6MUFPaxAy9FoYBQs1n09jZ2iqzi0mq34F0ERliFR8
         Ur4lRFOmR2D3NX/luHk0AqW4P0ARYDV+zFioXl9uRxGdDna8U6XoJ10gtLfhbCZ2Zg6e
         +ooJaUOhh6HkzgHDKKLHmLjIHK8Hz2M8Byd1FkH4IUQSIaJLbsVenEKoZXTNYncDQOBO
         YtxCYvDlJeN0X25XMEfhOX2Aw7KRorJ1gGVKzH6zRea/l+0mxS9h7pCTGc/IeAgbELjj
         NgJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fd8wEs+i15hpkNHpuReQi7S2sUWplSYq6WJQupzHG5w=;
        b=o64LBGH0xNtP4CNq7SQED8pJfrawL1DdOcOzaUFRCuqNuRE2wBZyk5NXP5phLmblHL
         G28sbx+qtWEUQW24XGdzfkvXos69+vCnwP5m6Y8YigQ8CGzQtI6/b1UJl2neAZkOfheN
         zOts/2kGQ9TKWCl8lkMJ7iwqNZ2Su8JllKq8k0iUcqXwQBsxpT+vdG2Bqz/BXQafojo/
         /+mWYv4aKbP251xvrn6ibaIwAbDkJpdci3OJP9yUVdI+oK11nEt77zKu9ILdyazmaKcu
         LDYdMKRJjDI8VV3p6s1kPamL42Wkzv9SSJrFneM6awnDZQh4S5dbOBuvwWvHPGilT6T1
         iYhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX+Zwdzn96Vy/5pH64002iaXy5cajEnf/qoQaVc+Eptv8Y7bVtl
	/zhbDpKry5sUiHDXrbqEQqA=
X-Google-Smtp-Source: APXvYqxg+jtvliNSJ5oWbMql1ljrTpH9X2mozhYFI+F5ovl5nSmKdK4xe4bbgwzrTu99vDPI6PkewQ==
X-Received: by 2002:ac8:1a9d:: with SMTP id x29mr97722284qtj.128.1560806832291;
        Mon, 17 Jun 2019 14:27:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ad76:: with SMTP id v51ls2845644qvc.11.gmail; Mon, 17
 Jun 2019 14:27:12 -0700 (PDT)
X-Received: by 2002:ad4:43e3:: with SMTP id f3mr23875500qvu.108.1560806832102;
        Mon, 17 Jun 2019 14:27:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560806832; cv=none;
        d=google.com; s=arc-20160816;
        b=gESgDBumGOqEeqjozMgQPwdbWFYyvrhKROPc49uAuJfhhIwx4b5hUfySRIgaK6v7QW
         5n4II3xNvb4BrXitYFAlnGWLeQDqdeU1zQ5mR5HIjNw/G5nzt3sgbSgXxa+gfQDR5Wvs
         ixvthG1eRM2oYZSxUDxK3aye0YLiSdoSQwyQpe7XAvpdg6MqzWTI05o9BRA+KdDz/rhB
         8+qyy7+b7kknQbCouSU3NkKIsWpBB2hzYTAtuXsvG6atQ69X9ChwmRwMIAARjaXYKHw1
         qmvXYcOca5apm2H91AOYAaiBthTiSnv3k1OfJEUVZoXfqc3pQ1nb8O4w1XSMsEYojUiE
         OPjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=M4b68R6nSZI+WAaX4DE0rJsE5LLmpv/VpN3uo1jtz7w=;
        b=EZEq4WaDI7f//ujgitZjecl7Jg1kKuU9TozL674S/NLusey/OG7J8ss3EC8jrvNFmi
         ntEZEQyVjq3MtPTkAR7qYSb2iycNtoyoW4lOTlTmuL9w+rPt3gjVxjoH29rLNnbqQUP7
         xR2b33P9ftMA2N7luoEVjPnj5mgFFvjDZjMAOislBiF0eQQb/D4AIGXeSbws+P/QYp2s
         MNBnhgg8Gys4Km7CsNDiMKsMUiEaOTdFiPAXJ0syBpo9M4B5Nipkj8GRhQYBQywMj76n
         YySzB5xxg8MFQ6m7GMtuZForY8YH2Jc8T+xT9OmeJo1+zTXRFDNGV43rJ9RvhqQ0Jenw
         nT7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=uQoY7v5M;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c188si620725qkb.2.2019.06.17.14.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 14:27:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8331E20673;
	Mon, 17 Jun 2019 21:27:10 +0000 (UTC)
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
Subject: [PATCH 4.19 70/75] x86/kasan: Fix boot with 5-level paging and KASAN
Date: Mon, 17 Jun 2019 23:10:21 +0200
Message-Id: <20190617210755.943656383@linuxfoundation.org>
X-Mailer: git-send-email 2.22.0
In-Reply-To: <20190617210752.799453599@linuxfoundation.org>
References: <20190617210752.799453599@linuxfoundation.org>
User-Agent: quilt/0.66
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=uQoY7v5M;       spf=pass
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
@@ -198,7 +198,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!pgtable_l5_enabled())
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617210755.943656383%40linuxfoundation.org.
For more options, visit https://groups.google.com/d/optout.
