Return-Path: <kasan-dev+bncBDXY7I6V6AMRBKV63K5AMGQESWCQGQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 865899E8C63
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 08:41:32 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-54019e668bfsf712515e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 23:41:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733730092; cv=pass;
        d=google.com; s=arc-20240605;
        b=GawePfgGnXivTaEFZ7/yj6RvlHjQ0LviHusm5u+97WvDoZwYNaskY1kefJKCtc10Aq
         ImaTtlLLQNFqwUSh6YzQ36jZiqHofizmVXkB3WDSjhY5TAJofHKVV8jAWNpQyExHWxdd
         eUhASOqNJ5vutN/9tYkLHk067KaJvzM6ByDITibk689EwySa0HnnloPToTMphwLkd/lW
         XnYUldAnyh61ukBI8siRwWaKP0RR6sQmWvEGGHRhd2AjJutgXo59ikqCD82+WmTaRggv
         k4TCo0LWHXD3YZ6dUcCE3uVdFhgwf351sdJKJraHPem+UTO2uJF75Q5ib5lCVkN1h74G
         lwfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=iXuhzmolCaLDDHQ7pobfRGJJnCrufQy6GNB2WpnVX54=;
        fh=LXq6hmnjeLC4pXpC8Ggfa3eZCp0Inejq1EFzseksQmE=;
        b=VOOdkbbV61WXuD4xlxIOsiB3Q4yO73ra9p2h8t6y36TA3DDpqSvCYDRQSYjGwx9MXg
         G0xXjMfoOeZz2SDf2oPUntrC6tgBVYiekrR3XQ8QcsXq+PiUuLRFWJaW009efznh4ypF
         HvnLzPSU6zQy/w7+7YTHvDbYRiiRk6JtvSs7VW2ro+aJyQV9X20VOI7iR7eCdRkdeGES
         v+PMmMHptPq5zT9lv5CZjhFl4I8cVHYqcxcf0syCzLcXA4m0N0tn8N+McA94IGPhFtYK
         xHdCwxO7men4Xvgt/Vxf3SVQ99B/nc77Kqm4eSWSkQsAJ1dOQiJEHym3no65ZjJnbPKI
         gd+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=i1ocIrps;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733730092; x=1734334892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iXuhzmolCaLDDHQ7pobfRGJJnCrufQy6GNB2WpnVX54=;
        b=mlh945nzxQXULDhI8MvUZi+I3aMNeABJ2LiRBwVM0gOzyg9Y/M/jICIdSnFl68ZLOy
         +fuF5FBQrW/eToKNaZlsDcYgbzWQojRK2O1i9++WaOogR6qTbqg2UiVrQd8d6aRndiGn
         W7VZrGrfOoPX7BNlpBNuYU9p/2tm9WbixaZBNhdK6opfnxE0VWvK4A4yp43bhyoymbPs
         rdzZNjAhIkftUtQgXQpc8sbaK0WvkZ0YKYX/Aa+WRgztQL1y224Eeyls/PUEAgXG6vEo
         cFTQlZgj3BqYJeX+5vPsjS+r2bP5oaBrCfGcZMiSY9QCTWLYg99yjWfH/bKSGR5pjmwm
         2FpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733730092; x=1734334892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iXuhzmolCaLDDHQ7pobfRGJJnCrufQy6GNB2WpnVX54=;
        b=g/QpkPE7rbWW9GbSoqhg+Ci97UwcDhJ6bcOVMJ5v6hfPjTeOoy0kVMJLezHXz2BcWU
         Vkzc4yGy0Aj8ra6RLekAO1hcsBxCXYg+chHWVLsltzeIU76gtK1Or9ApF9rmwa4Swj6P
         dnhp4E906deolekdUmHUNp7mL9KQKAlzmTp1YCkV9S5RvGpKLi+rox1B+nRVePIuzlIJ
         c2mR3YvbuvpsWH8wg257+IjXjOzz1N/79RNy282y78AO1OU/vRDgCJERH4H0WRj74JzG
         vS3o8blagGOogJ8cYNolcyh0FosYwmHOsY8ut3yBF4x0tB3IK1dRUk+0aC9nsMgUOT2y
         OTow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU38qFZlAZA84s+CE/xwG7YXvYrvg6rVdJErTx9tAh3lMhAXQ/oG7Qqdv0AjhwmGwHCNwXbNw==@lfdr.de
X-Gm-Message-State: AOJu0YyGmmXBEJ7c9j8FSf++JW83990tCiQgSKI+R/khmHKJ5YiGgqD7
	W4JgAWtAjNipoFJ9pUFqroBka1jU9TprO0PLNYzL31sC8g4gWmp8
X-Google-Smtp-Source: AGHT+IHyxDsCs/koFkke7TQ8t8ZYU8xkqcFrkLU/PPffYf37Lxgklb+MliAHEpXMb2m3MiqCL1Hfjw==
X-Received: by 2002:a05:6512:31d3:b0:540:1d58:da70 with SMTP id 2adb3069b0e04-5401d58db92mr1309383e87.4.1733730090910;
        Sun, 08 Dec 2024 23:41:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c7:b0:53f:22fa:27d6 with SMTP id
 2adb3069b0e04-53f22fa28e7ls29292e87.2.-pod-prod-03-eu; Sun, 08 Dec 2024
 23:41:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU08LzfG9IXbmHy7mXyWF8PB1nZncFoTNns8jLvPzl/NIVKdomLTWHZDmsNi2BuhU/U7HpwUuqxwVs=@googlegroups.com
X-Received: by 2002:ac2:4e08:0:b0:53e:239b:6097 with SMTP id 2adb3069b0e04-53e2c2ede4amr4130458e87.50.1733730087993;
        Sun, 08 Dec 2024 23:41:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733730087; cv=none;
        d=google.com; s=arc-20240605;
        b=JCAtrLT94YzrU6TtI2ZGGpqPsWErV9dcR1Dy/TOT+FPcBp3+fFBGgP89T5v+ONF1si
         Whvl3eGT2by0MDmCT13ID19RqAO6mk8u6EVwWC7cqUIyA40VR90hKClJS81f52dzV67Z
         sWX8oq37L3r4NaKQgTr9ps02Ifviw+HlP29A8W8yUZf9EQ0Rlh5IClNnWQwyd6Ysk0op
         qMg/NOvO/i/RV4mkTiarzz1S5Ni0QnU/IplI3HHVZpzMu/8ahHO37KdxMIdEiPa2Jipf
         vMv4HZ+pU6hMcFxIIBQviqJeGyLvGy01B7orX2unNI5/ZfGB6LQFmWEwCIxcNoqzOgP0
         lUjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z3RCak58lMoNTf2/3PYYExuMpiOUpiJrkwR5/y5GnZY=;
        fh=9q59LBcUgurW1NosHVX5VRXnteCUXJTX5SwAfZPAqN8=;
        b=jm8+EjxqgP+LKhlSRjfoTT/wxoP/S5Ol0GvhjhYrBSG/Vdo2s3ifaD5brLlw7FVmtN
         dTobLcPm4kreWU1jJ5VezU4LajLNRBIRrYMQIDMsyPcMtd+LPb+ABBuHYrhk5ymWEAsF
         9YP4ILKxgObJY6FyxxBXbqQxcPlPYBmkstnM8wlUkJFhf3rzjdhRz03Xd4euwjZNEP3E
         Ug1yd+zTX2+Mq9ZndS3EJbWI1vasRwFFcuwB0bWAWvfWRtyeUC6OtZwl0cHoLgqygulG
         UEiYvwYDMbpiuOv+SXr5tIGprzxK36El+0P6F6xKPoV4nwzM0L7uZiJrDrZmOuA4SpAo
         hYsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=i1ocIrps;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5401c92065dsi40963e87.2.2024.12.08.23.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Dec 2024 23:41:27 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-434e406a547so11739985e9.3
        for <kasan-dev@googlegroups.com>; Sun, 08 Dec 2024 23:41:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV+QDsL7Q3/BJhY4vRb7MkOhrcKkZvqfozLe5bPnu8UhxZZDPXdk5F/h7FhFpyM7CE29elFJUcps24=@googlegroups.com
X-Gm-Gg: ASbGncvPpSOME6tX7Cyoi0a7PTzzWGApTskBVp2tKS1GFRjZCbeUzmfcGzO/RWOiG4g
	7ECvC2BNLV/PwEod+jQ4lHmfYJ/KM41NyotYmOoScmKF5zMomoV/25MqpZj+biqhXvrYGruyG83
	elqJiT5dqiFmCOHFMY5QpmEFlVAmIeUXYdBG+gpDC3a4+SYZeXA2TUjiBLPANtwMLvC9G8hZPJM
	PFajlfLVNxccBiPkokbxdszfcq5XaKPXKVb9zzV1Eh9R2nWl8miCFr3bQMp/xT0879Ln89It97/
	A0HV3iNJjhoftgYkOA==
X-Received: by 2002:a5d:47af:0:b0:385:ed16:cac with SMTP id ffacd0b85a97d-3862b3f4930mr8270534f8f.56.1733730087202;
        Sun, 08 Dec 2024 23:41:27 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-472-36.w2-7.abo.wanadoo.fr. [2.7.62.36])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38636c919e5sm6471730f8f.18.2024.12.08.23.41.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 08 Dec 2024 23:41:26 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Liu Shixin <liushixin2@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH -fixes] riscv: Fix IPIs usage in kfence_protect_page()
Date: Mon,  9 Dec 2024 08:41:25 +0100
Message-Id: <20241209074125.52322-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=i1ocIrps;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

flush_tlb_kernel_range() may use IPIs to flush the TLBs of all the
cores, which triggers the following warning when the irqs are disabled:

[    3.455330] WARNING: CPU: 1 PID: 0 at kernel/smp.c:815 smp_call_function_many_cond+0x452/0x520
[    3.456647] Modules linked in:
[    3.457218] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.12.0-rc7-00010-g91d3de7240b8 #1
[    3.457416] Hardware name: QEMU QEMU Virtual Machine, BIOS
[    3.457633] epc : smp_call_function_many_cond+0x452/0x520
[    3.457736]  ra : on_each_cpu_cond_mask+0x1e/0x30
[    3.457786] epc : ffffffff800b669a ra : ffffffff800b67c2 sp : ff2000000000bb50
[    3.457824]  gp : ffffffff815212b8 tp : ff6000008014f080 t0 : 000000000000003f
[    3.457859]  t1 : ffffffff815221e0 t2 : 000000000000000f s0 : ff2000000000bc10
[    3.457920]  s1 : 0000000000000040 a0 : ffffffff815221e0 a1 : 0000000000000001
[    3.457953]  a2 : 0000000000010000 a3 : 0000000000000003 a4 : 0000000000000000
[    3.458006]  a5 : 0000000000000000 a6 : ffffffffffffffff a7 : 0000000000000000
[    3.458042]  s2 : ffffffff815223be s3 : 00fffffffffff000 s4 : ff600001ffe38fc0
[    3.458076]  s5 : ff600001ff950d00 s6 : 0000000200000120 s7 : 0000000000000001
[    3.458109]  s8 : 0000000000000001 s9 : ff60000080841ef0 s10: 0000000000000001
[    3.458141]  s11: ffffffff81524812 t3 : 0000000000000001 t4 : ff60000080092bc0
[    3.458172]  t5 : 0000000000000000 t6 : ff200000000236d0
[    3.458203] status: 0000000200000100 badaddr: ffffffff800b669a cause: 0000000000000003
[    3.458373] [<ffffffff800b669a>] smp_call_function_many_cond+0x452/0x520
[    3.458593] [<ffffffff800b67c2>] on_each_cpu_cond_mask+0x1e/0x30
[    3.458625] [<ffffffff8000e4ca>] __flush_tlb_range+0x118/0x1ca
[    3.458656] [<ffffffff8000e6b2>] flush_tlb_kernel_range+0x1e/0x26
[    3.458683] [<ffffffff801ea56a>] kfence_protect+0xc0/0xce
[    3.458717] [<ffffffff801e9456>] kfence_guarded_free+0xc6/0x1c0
[    3.458742] [<ffffffff801e9d6c>] __kfence_free+0x62/0xc6
[    3.458764] [<ffffffff801c57d8>] kfree+0x106/0x32c
[    3.458786] [<ffffffff80588cf2>] detach_buf_split+0x188/0x1a8
[    3.458816] [<ffffffff8058708c>] virtqueue_get_buf_ctx+0xb6/0x1f6
[    3.458839] [<ffffffff805871da>] virtqueue_get_buf+0xe/0x16
[    3.458880] [<ffffffff80613d6a>] virtblk_done+0x5c/0xe2
[    3.458908] [<ffffffff8058766e>] vring_interrupt+0x6a/0x74
[    3.458930] [<ffffffff800747d8>] __handle_irq_event_percpu+0x7c/0xe2
[    3.458956] [<ffffffff800748f0>] handle_irq_event+0x3c/0x86
[    3.458978] [<ffffffff800786cc>] handle_simple_irq+0x9e/0xbe
[    3.459004] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a
[    3.459027] [<ffffffff804bf87c>] imsic_handle_irq+0xba/0x120
[    3.459056] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a
[    3.459080] [<ffffffff804bdb76>] riscv_intc_aia_irq+0x24/0x34
[    3.459103] [<ffffffff809d0452>] handle_riscv_irq+0x2e/0x4c
[    3.459133] [<ffffffff809d923e>] call_on_irq_stack+0x32/0x40

So only flush the local TLB and let the lazy kfence page fault handling
deal with the faults which could happen when a core has an old protected
pte version cached in its TLB. That leads to potential inaccuracies which
can be tolerated when using kfence.

Fixes: 47513f243b45 ("riscv: Enable KFENCE for riscv64")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/include/asm/kfence.h | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index 7388edd88986..d08bf7fb3aee 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -22,7 +22,9 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	else
 		set_pte(pte, __pte(pte_val(ptep_get(pte)) | _PAGE_PRESENT));
 
-	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
+	preempt_disable();
+	local_flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
+	preempt_enable();
 
 	return true;
 }
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241209074125.52322-1-alexghiti%40rivosinc.com.
