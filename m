Return-Path: <kasan-dev+bncBAABBAGJSKBQMGQE365XHJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D8523504A2
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:34:09 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id g11sf1977102ilc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:34:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208448; cv=pass;
        d=google.com; s=arc-20160816;
        b=CjJje2TINVQ1aFWqYU4cekTiFTRmAJZ/UVsbcbx1rR7HgJGbaV5WtSck+U8YkIg3km
         05YJdP3HQ0jWnhY/sLhZipRXUrUdWZRMq7g+zv5HavP/itKtCC1/LVt7mAEjoYyPQt3J
         3neZgUEu+thRVLUo6ehhcE7Zx+5XZikgtPfr4e5iNW29w84nzWeKZaEis2yacQsJl6/2
         SbAHzx+ypAqtz8LTRTfXffdvgRCgBjI5iEIEKwEqUh3IbCGP9KJ5lhSn/gUx9SK4XIUs
         S0HE5hb2uqpyHndyM73RqE2+YKR97EG9s7ZMTdX6t05bNSueG3EIOjsFPHfi7PnEtOQ1
         XkBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=K3vS6D196PuO18fE+Hc7Ip0/bstn6CyBZnQTqrgeE2o=;
        b=j/yblYJLCIdbVWOjHYtGqUG7XAQejRx7OVe0f4cY8JLDRpLvjQusxx5MnMENVm8I7/
         USxfASUpa3gi4ZCaiF97xlVnZzD5mC98ISW+E7JfwA2XH0I36LGKH6pielm9ON/wpOEi
         Sh4GYY86CQ1CNysChTOgKnoNlwPLHI2xGTlMngVJbsMpnVbE7p7/JjvEY0AgiTJ43Shb
         OPT2H3mT6s2UpQHOY0saStEAY8vMO9r7nY4jyiD6QJV/ofH6sqViKW/vSKBY1gqNOHER
         /rqTc+hNqG1cN+EobqBJVCG8dn0SKXwBDosNMxuds+DBfENwIxAg3WqYlLoLfBd9Qw7o
         RZSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=H8FUPEu6;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=K3vS6D196PuO18fE+Hc7Ip0/bstn6CyBZnQTqrgeE2o=;
        b=IDpMEyLuQoJAp4KnKrkSOH7S741pX1Zz4XiSV4m6Wnw2k6tfKLDhFSsSPoyWwyub/t
         o/s+U4k/HjIYPC6FgbgL/PY/uSJRVKbqz0/usPg9geEDvVyvKvaBkBh1ZzqfShLW0Q5n
         UmdrAamChh97YcBB+urk/QrCSWPS1PqcGRxPmLGeAfg50xeTP7uo3K8nTySDjOfT31ls
         tcRcpm2kZA2L5j9n7k9sDzuJErQd7jAwnJccE2Ks3QitiH4o4v/90kIgYQYNX5IdGMeW
         63DBTbDxLYK6Bw8uz74U0ld3avfl1lfRY/5fdfHR6UJia+70LWAwQT01F3xpq84v1kP1
         yPkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K3vS6D196PuO18fE+Hc7Ip0/bstn6CyBZnQTqrgeE2o=;
        b=iZtKqggijQZlPXOFetFKhdBruaHIhgG0bpGI7heSbLVf2DJXTwpeCzqR8W7vzDVfZE
         lok5reJEkNV+jJMikbNq83PpyXrmVg3MDZKQmxm8GKIG1Zs+w8jnRMnLZdHkEyWb3d9m
         9g9Lvh++9/vdodh8BtY7eIZRcBtvLuLu4R3tm/0r7PwtswTI/6KEOG55ehwef3ZMcdjf
         VNwQaHwF+4I4cX7belfLtQYwUckTOSVJ+tjwFlqU1DLrLSzEouR0mbhZxydt7CMrwFQB
         oo9vHdiZaa/On/vb6qJF7PhKXPRta26452NBfX2jdTlwd5rYDj1tyWVTaCZhaOfTLDTi
         /rxw==
X-Gm-Message-State: AOAM532y/9R7/hgWmJHXh1GSu0lHCgw9FOMllYlIMC8GmcuIclQ7Fk8A
	cm7R1cKG6hEorybrGb2FBno=
X-Google-Smtp-Source: ABdhPJwAbOGwFn9BZBX9miCvFw57qKNizg1VelgIprkQNhd9S2WhjjuiAQ5GyQ+Pmn+aWZf8GqyyQA==
X-Received: by 2002:a02:aa92:: with SMTP id u18mr3766020jai.119.1617208448267;
        Wed, 31 Mar 2021 09:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d82:: with SMTP id h2ls594152ila.9.gmail; Wed, 31
 Mar 2021 09:34:08 -0700 (PDT)
X-Received: by 2002:a05:6e02:1e01:: with SMTP id g1mr3242683ila.192.1617208448026;
        Wed, 31 Mar 2021 09:34:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208448; cv=none;
        d=google.com; s=arc-20160816;
        b=Ukc7B9C5v+no/U2QzOk+UY74EVut3zABdzS/+V7Mv4M5/44E/R+zu7r/As36jsbhp7
         k9wJrxAGaE4kBNJAtHwu6d7PnPZCjCCc7VkzhSDdPk/nV8JJm+/BpvO3xcBpqGhPsxGL
         8shIdD9l2OLWika1BDCcH+Q86C6eEx/8Lupug/3polw+Ky3BkF8auMFNPSiXDM2svRak
         kdw/KizKfG+kqb3MCMrUr6bTKyG82FajgtcUpFsUjFb3U7BSx2FHwY2NDuJ8UG3eBQNJ
         Qk6XU7AtzY+y3nlC265O+EQzHWhlH/x4Es1wXorUstMB4aN20H3v5XvFtkiJC3AIQdPN
         o73Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rWZY9UwzK3VhbJb3NlTJX8W59dG2h3SG5jHHtJwc4J0=;
        b=M1nGQZqGg1Reblzc0FJkJF2RObFrCutYd0blrmoDNv7r16XPJIgx2uJ6vbhgkUOmO0
         GFct3UNeKXNoRLFehh8YwFt56JYpAbUmeL68X+bvbY7sAL4vjyFdiC+GYYHzT6xwaN9s
         yFrqC4ixpqYajF0iL0QkNyUeDp8c/xpPdKwuLQ5RpcxjtnGX1dy3mkRlZpLfBhJhCkWa
         4ZUjFzOx2U2GKAk1x+5B21d1AjLZgzNLxhi926kxDMbry4jW+HgJHE3FmyyteLydrBVV
         Ak3/ejGcarvBmE7ZX+lOl63Jutfhpxc9a+ZaCdHvM/X2p8WkOBmSZa0x1PI/32tCkyGY
         ENLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=H8FUPEu6;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id w1si175498ilh.2.2021.03.31.09.34.05
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygAHD0t1pGRgMb96AA--.13595S2;
	Thu, 01 Apr 2021 00:33:58 +0800 (CST)
Date: Thu, 1 Apr 2021 00:29:00 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt 
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin 
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey 
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, " 
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov 
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko 
 <andrii@kernel.org>, Song Liu  <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend  <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson  <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2 8/9] riscv: module: Create module allocations without
 exec permissions
Message-ID: <20210401002900.470f3413@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygAHD0t1pGRgMb96AA--.13595S2
X-Coremail-Antispam: 1UD129KBjvJXoW7GFyfWF4rGrWktry5Wr1xXwb_yoW8JrWUpr
	4xCrn0vrWrWw4xG3ySyF1vgF95Cws7Gr4Sga9rWFy7AanxJr4rAwn0gwn5Zry2qFy8ur48
	Wr43ur1SvFyUA37anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkEb7Iv0xC_KF4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjc
	xK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG
	64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2jsIE14v26r
	1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwACI402YVCY1x02628vn2kI
	c2xKxwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14
	v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkG
	c2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUCVW8JwCI42IY6xIIjxv20xvEc7CjxVAFwI
	0_Gr1j6F4UJwCI42IY6xAIw20EY4v20xvaj40_Gr0_Zr1lIxAIcVC2z280aVAFwI0_Jr0_
	Gr1lIxAIcVC2z280aVCY1x0267AKxVW8Jr0_Cr1UYxBIdaVFxhVjvjDU0xZFpf9x07jnCz
	tUUUUU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=H8FUPEu6;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

The core code manages the executable permissions of code regions of
modules explicitly, it is not necessary to create the module vmalloc
regions with RWX permissions. Create them with RW- permissions instead.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/kernel/module.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
index 104fba889cf7..e89367bba7c9 100644
--- a/arch/riscv/kernel/module.c
+++ b/arch/riscv/kernel/module.c
@@ -407,14 +407,20 @@ int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
 	return 0;
 }
 
-#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
+#ifdef CONFIG_MMU
+
+#ifdef CONFIG_64BIT
 #define VMALLOC_MODULE_START \
 	 max(PFN_ALIGN((unsigned long)&_end - SZ_2G), VMALLOC_START)
+#else
+#define VMALLOC_MODULE_START	VMALLOC_START
+#endif
+
 void *module_alloc(unsigned long size)
 {
 	return __vmalloc_node_range(size, 1, VMALLOC_MODULE_START,
 				    VMALLOC_END, GFP_KERNEL,
-				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
+				    PAGE_KERNEL, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
 #endif
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002900.470f3413%40xhacker.
