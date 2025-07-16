Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTUI37BQMGQEKHTV7WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 445F3B079B0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 17:25:05 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b8579063bsf35211311fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 08:25:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752679504; cv=pass;
        d=google.com; s=arc-20240605;
        b=aXgnD82lozxgp9GAMRcsvvTPTkXb2x/BjA5Xb2Lf5UYUT4whMwjm2qwm0sUwm432zq
         UlgPSuiQJASfok4iQWQATkPLAfHWdCwv9Oapjp9LukxtHzZR8zGYMZ3Uqs3Wvys/rxYA
         1ptZHXOp6sPz4oJwUJH/YhhqJNh3773i04H4OKqsra855HyqkOzcxeuZH5NduyEVT65j
         lLy2OJEGrDvS4pGFubfg+wFYBti5oVYqv6XDov+w8gqV6NwbMdNswIABsTI5NhG6FbGk
         4x/9ngBjbSBkjkSWzeiZg/QznZt5g+WBsSUk7Qc5PJYiH7AlRzpDexT2DtZZjSybrjFC
         1mqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=byz66VxRSnIIqNtn+cFW49W7UQPe3QWa3EZ/x/HaxrE=;
        fh=s0vFuoBsR0WQjeqIgB2d/B//Sd+k2aOXjzKnsH5i8d8=;
        b=VN+08rd6dcNT1T1WvKm2qvpIOuN9EoVHE1qAG2/DdRpQg9VHGDt3/zTqDjS9mEWVXD
         fq3cyOHeRASxPKDBVgxr3obX+JUWJTwPnajR6VgOt3LiSuOu8MXiA4zb+KCwELjPY2J+
         PDNkw023020UiP4HEbtOTN8ZJoKeGuze85PZvQPpKl3aPxk2LHkF2g/fhq+K4eWCeAAE
         pTl7R4Hg/3L+zuJ3uO0UOaAaXZzNWmxaaOsLPepUUuBGiQlCqDWSul7an1mpeC7nDkmW
         dEMyqCMzWUOgEO1x+AlqEqql2QJ9+hRVj9LQyiOu9aE8xAvbj5dBy0/RupD+NUvcYJAr
         MVgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k7TBPmuG;
       spf=pass (google.com: domain of 3s8r3aaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S8R3aAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752679504; x=1753284304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=byz66VxRSnIIqNtn+cFW49W7UQPe3QWa3EZ/x/HaxrE=;
        b=tU5brXVp3FIcoz6ZTaGqGCRfb0Q6/7BDImtKR3OQFCbKPPJW4+HPtFZmR1wZnUu5VI
         BmfSGbU4AAc1v2zCqdeHRt2g/Q7Bmcae1fFbaCzohtZC7uGiB5PMqq+iE+BiKRfKISIo
         WxDUf4YRdWKmp2IKf8D8H8kPLe+vxzoZUM/AihxFm0AZW0jt0vSEvF/TZ/sS2I605GqM
         ykLsNjaeQN3gc42jTCNq9uBx6ZRyYukQ7/SQht8tKVcOwc48wFgnYx+lNI6tjE4Zgccx
         nt2ynsX51KRz1yd60uuKDc4YWqvmnhN1h38mkz9JfaUg1scydjx90mFBAQhd4jiJPHY0
         08nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752679504; x=1753284304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=byz66VxRSnIIqNtn+cFW49W7UQPe3QWa3EZ/x/HaxrE=;
        b=El61RlJFzrkYVXSUzZ8YP6ZurwWFVY7uLYR8pExfjcWyAcmBd2/Auy2cIrLuadA8RH
         VEhccPsc7lR198Ymv09LTcxty18AJiHF/NQG4CSah6WUOoIdXi5BaIySt9C1HVz1CtF3
         HDt0U+BE+q+qBWLp+2RnhCgJckMw8sEtU0oubA1EMKkOnnQ+JXaiqj0NPbJTG0LsvObv
         0ydYL4Xp6utRbyaucWCvI2L3C/nfwUDOCqg0jZWQjgSE9h5o/ctbFxvS7Z/P0kxyQXi5
         Y4mx/cLEpbDfulCs2oA4ozoZ02jUa9SksI1gQGPDA+4JvEaUuiR+9vHLLrf1AMxhMSnj
         vAlA==
X-Forwarded-Encrypted: i=2; AJvYcCVpzNUNrhDkFEJayCqAaJnXQkjzTAx6tsFLFEZxZ1rkfclkrBnbyiKfxkNhwdr/0DQ39+IOAA==@lfdr.de
X-Gm-Message-State: AOJu0YyDLh51Y2DmDTveN8ir7k/aWc2yTDjKszbiK9T8jzD95/dC43UE
	yttnOYlUpSMiEvN9yHWEZByUA2IB7nH1TZtF+K8rPusfnyocD+4IT/rQ
X-Google-Smtp-Source: AGHT+IH2udIMHElYNcG5GSJwqqBpPzRXg+zE2pFpquBnb5C/NGxupknVPgeeZ5xqG+NjTIuBExcEHg==
X-Received: by 2002:a05:651c:3254:10b0:32e:1052:5437 with SMTP id 38308e7fff4ca-3308f5df7fdmr7031341fa.22.1752679504075;
        Wed, 16 Jul 2025 08:25:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfF84J/eOtW+oYQYaaCY/dnjJD9VCD5+Jc6VfGHEksU7w==
Received: by 2002:a05:651c:31c6:b0:32a:dddf:7d59 with SMTP id
 38308e7fff4ca-33097ee9775ls241521fa.2.-pod-prod-05-eu; Wed, 16 Jul 2025
 08:25:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsS8Aqlt141407hDnphETm1B/nEBkeONUXf/las3m7DV/dfRSy0IWmWNLenmw15WAn3go1PPAe1X4=@googlegroups.com
X-Received: by 2002:a05:651c:54e:b0:32a:7baf:9dcf with SMTP id 38308e7fff4ca-3308f60be48mr14200491fa.28.1752679500134;
        Wed, 16 Jul 2025 08:25:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752679500; cv=none;
        d=google.com; s=arc-20240605;
        b=AiXPNyiwLuWtmRiZEllZPFjtP/TKKwsJGG2yIXJagCnhA4NJPOg7swqNVd0sOcmDj+
         mCELYnffSN17Q/Va9btBb/WdvDsI0PcV+sYeBiRMJvNQjodMvkqtarfz84cRjrBxMfd+
         5x5O8MTcxjrXC6GIuAA8sLpqwv6+ip20BWUkcQGF3mbbNh3095B9hFpJuVqo+zKA0HtK
         9IJWJW5r7yIQF2cbkLQkk5k0DSRhnsKHY6CFYlCcr0DInO59fxnI/Edj9EB0aRsJ+33b
         598fkkP70sv3Ntzv9fA5vS3N1h7IWVV0RXJCXhhRKxenN+QrCi0yP7GJ6SfrQO9xPGaZ
         ReBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Y020Ei9Bk/dDr2jy5oIxQhB4Mux4H8qkRk2Nk2X5B6Y=;
        fh=IyEjVCrwSEkycayUmOVRHNc2vrjFYKCpAsNJrUYr1r4=;
        b=XJ3x2Kf2AjXfyDnHkdFuUoK819LCH+tiqVYbXzhheYu+xjvDkAaFFjSoounOswRZ+z
         HMwuSYLuYCSMFp7usV+TWyaKYtOoNwkmaU+q8wm7F9sSdu2Qcfe1vXk1+PxOpgFH+nej
         eXYjAuT2HiXrX8A4iRgO/sH0AapmuX9hAs5pqsaFPycftF3xplV1+CRUsfXN6h7XC7nP
         z12bdlpVQRX3m3MbV/pbAUK1Lvpqg8Gytu5GjKSABQ5IDPH9kxgJxRLfSX+rBMoebB1I
         7H6VFuRm+02PrSGgU8ZZAiUN7Zgjd8TRFjkTCycNkWzeQXdSjXEasltN4ltKebJs3rJS
         z9/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k7TBPmuG;
       spf=pass (google.com: domain of 3s8r3aaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S8R3aAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa5d91897si4061711fa.5.2025.07.16.08.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 08:25:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3s8r3aaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-451d30992bcso53510715e9.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 08:25:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBiQM5eoEgKubAfhpHNWZ1BD/AQqRrBzoUMSAzE/sE1NZKF3g4aH/lKY4gKpwKAE/7JVQUGw3Jx6s=@googlegroups.com
X-Received: from wmbhe13.prod.google.com ([2002:a05:600c:540d:b0:43c:ef7b:ffac])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:19cb:b0:43c:ee3f:2c3
 with SMTP id 5b1f17b1804b1-4562e37a0ecmr26916265e9.7.1752679499601; Wed, 16
 Jul 2025 08:24:59 -0700 (PDT)
Date: Wed, 16 Jul 2025 17:23:28 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250716152448.3877201-1-elver@google.com>
Subject: [PATCH] kasan: use vmalloc_dump_obj() for vmalloc error reports
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Uladzislau Rezki <urezki@gmail.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Yeoreum Yun <yeoreum.yun@arm.com>, 
	Yunseong Kim <ysk@kzalloc.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=k7TBPmuG;       spf=pass
 (google.com: domain of 3s8r3aaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S8R3aAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Since 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent
possible deadlock"), more detailed info about the vmalloc mapping and
the origin was dropped due to potential deadlocks.

While fixing the deadlock is necessary, that patch was too quick in
killing an otherwise useful feature, and did no due-diligence in
understanding if an alternative option is available.

Restore printing more helpful vmalloc allocation info in KASAN reports
with the help of vmalloc_dump_obj(). Example report:

| BUG: KASAN: vmalloc-out-of-bounds in vmalloc_oob+0x4c9/0x610
| Read of size 1 at addr ffffc900002fd7f3 by task kunit_try_catch/493
|
| CPU: [...]
| Call Trace:
|  <TASK>
|  dump_stack_lvl+0xa8/0xf0
|  print_report+0x17e/0x810
|  kasan_report+0x155/0x190
|  vmalloc_oob+0x4c9/0x610
|  [...]
|
| The buggy address belongs to a 1-page vmalloc region starting at 0xffffc900002fd000 allocated at vmalloc_oob+0x36/0x610
| The buggy address belongs to the physical page:
| page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x126364
| flags: 0x200000000000000(node=0|zone=2)
| raw: 0200000000000000 0000000000000000 dead000000000122 0000000000000000
| raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
| page dumped because: kasan: bad access detected
|
| [..]

Fixes: 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent possible deadlock")
Suggested-by: Uladzislau Rezki <urezki@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: Yunseong Kim <ysk@kzalloc.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kasan/report.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b0877035491f..62c01b4527eb 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -399,7 +399,9 @@ static void print_address_description(void *addr, u8 tag,
 	}
 
 	if (is_vmalloc_addr(addr)) {
-		pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
+		pr_err("The buggy address belongs to a");
+		if (!vmalloc_dump_obj(addr))
+			pr_cont(" vmalloc virtual mapping\n");
 		page = vmalloc_to_page(addr);
 	}
 
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250716152448.3877201-1-elver%40google.com.
