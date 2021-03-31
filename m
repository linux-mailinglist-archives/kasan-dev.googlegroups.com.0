Return-Path: <kasan-dev+bncBAABBLWJSKBQMGQEPF6XDSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id CAF813504A8
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:34:55 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id z140sf1357373ooa.10
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:34:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208494; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZyaGzYEt7LD0w+Yi5L0F7jfQj0p9sf+uHZxxldsFW00dHqc2JqyHtoYQM6l5uE3lHG
         tJKuwmLYgr+C6h89qiu7R9l5zMWcf+C1I+aVJhEBWmumUvebVdfhcSkMaLDQT+du991h
         f11wJHUk5I/pZMN6IegzaKejhRyGtUblPfB+cDu/fjR1HQVXVGZQMseWAVM0zlmH/sUF
         QBQkhuCoVXwLRTnBssN9UtpxhaJhgq7Ef/TdCa+ur7VsOnIqFvAP3ix65t4yVJKy0HYi
         Nt58bq7FHt6KjU4ztUwElbEVZmx3ZW6cFQzUIaUNwvxjse4g0aq+8fjoC5M5p3+pcvPK
         6rIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xr4jhmQGVhn6Rf/QQ3JtBdSMb0y4PuAOlJUZAwmOTbI=;
        b=zczTSCpRpDWinIbqDQrKSuo8mIj3+7Gm2EZ/+fcxG1FDoVOJO+YqreCF+/zTYBymCp
         uSrdM5iIAGAUZc1fqgxCrQiaNS/4H8NUV/LnZx8u6thmGwBM+CBIl1yBYybmxbZnFa6s
         bfv7hxsgjWQFX3FBHmOT8Y3zg9xS2GjY97iBp3G7zJAyRc5bSBJxdQR6THu7ZSMK0CHS
         M52mpS0T7ArKCQpcHR1MKLa5XRGzHK/3KEkYZj7/P/sVBoP9vYrPPlKTyiMCoSSemhpe
         T5F74p9AFpUPKVlU8gxdocNYPo3rDXo2I/szy3HBsg+CRnP+8IBb6nKUBOeZK1dzcCJ2
         n//A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=rEPMMiUz;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xr4jhmQGVhn6Rf/QQ3JtBdSMb0y4PuAOlJUZAwmOTbI=;
        b=hS6yMdxXQIR7Zry699t9rGvJGXgF9riwBHUFKc2nUW5xnPFI4eHXNcdHtHbWUAFa7b
         AheunnA+aiXzxTR1U57JbWi96n9BrSbC67w73mnQjpssD6geH6y+4Ct2vhXIQ8uNVbNY
         y7FhFFus7G8hNLn5eGbNRBujSeCGkq98wvIICQweIUPuCwN73tiRUsX8qzGh9m6kJ/U8
         zX+ih5LWdsw+zHCifCDw3YJssC7YqEDXHsARnJHd5Q3jscuf96TKVf66d4JORbLvPleq
         fAsaAW7tbcC863UHZDNYQFkMEz3V2ZYkO0fr3uYL8ki0VjMlUIBSHh9In9A5rCv3Er5o
         /DwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xr4jhmQGVhn6Rf/QQ3JtBdSMb0y4PuAOlJUZAwmOTbI=;
        b=jCceaYZCv8VEMJFA01gDlv1LXtFrV2GUp2PPxk6Yd2S9fyvDF8iJTU4KvITxugqyt8
         cIVej1SU4ZzkrJMf/mDm63LCZ6MnlDpUG6stBJ5D6xp8CMkcq9WSZNZUhY760ZFGEa6t
         nnL8t77GbHWWWfKIKn6tmUiES1eZpT4Q9SiZUNv4xsRj+QdgIfE5uZDZDi1J6oAcJkuo
         YXlT+POTXA71kaGUSPQYTm+KbPPKtyinYWYHi6IDXOHNtAoDfZjHPPESn7oufJG4MqCY
         S8JCBONPfxE31/c4WeZ3XSbno8ohOJsZLOI67Pi4N90E+4vzS+4W8SqeWnOjPHTeKmeb
         dShQ==
X-Gm-Message-State: AOAM532Frt5HnitvmRhes1FCJ/S0/B3Fp7uRqrj0vG+J7Ee/gF/F46zf
	fbPQ0Rle52NBbDBKY9BYwfc=
X-Google-Smtp-Source: ABdhPJxuplkjY69lkp6MXliwTdMyvvaSoiMF6g/mHymEoKHxqt674XiWlSvSEGeF89CPqWbUtx6k7w==
X-Received: by 2002:aca:5945:: with SMTP id n66mr2775766oib.11.1617208494849;
        Wed, 31 Mar 2021 09:34:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4c55:: with SMTP id z82ls626074oia.2.gmail; Wed, 31 Mar
 2021 09:34:54 -0700 (PDT)
X-Received: by 2002:aca:1218:: with SMTP id 24mr2921824ois.75.1617208494603;
        Wed, 31 Mar 2021 09:34:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208494; cv=none;
        d=google.com; s=arc-20160816;
        b=im4eyfRHncJRCabn4rIIaE0/sgpgnwZjZnavopkRDMkuhWI0poWXB+FAQss0friA26
         jDrSbJVPwpWbnpwfBkcCvxEqz26khkHqnHNgy2PIZtCDaAkGts9rVNZijegeG44HuhlY
         YbsjAlvlnTu1lSW8rYK0dfJsG2f6JC6A6kUoUsvPHu7+Y3XtTUGUT4NoK16N3XmIRQYX
         vzOkUL6nXG3Ih7uhM3IX34fJDfNcUSXtYBqY6rCleklX8Krj+/TEe4ID0RV2TYmsKeYO
         rH4MF0bDQYF41Q3diIZLRyfDVMn0gAoxBaFVRCqp6wB/9kl089nXPxJW+RjdHI9PQUHX
         qi/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9CYVVSdbdIN1CqoSzahmxkYgo2mgL2GjKI5zP4cVXEs=;
        b=AXPTRAnqa3dzLupo+mQyWvzYiqjCjMaQ656bbrklvYmvptJAMnNgfRtNGLnlLG+uQ/
         2vd7V/N/+fKGRS3KK6Ck2gm+ClCHryA0JriJpBbV3jZLL3HT9+f5ayXG6xjoYCaLPgeA
         iQfdvIg2WotCWJ5YzNQ1TfwSY4iF0gT8dNoS9bEsPlll0EzB5fwqKdJ0ebofKOycISsT
         apPQqbuyswjUNODeV7QZ4LTpA5aquzqytG5UnwYvWc3lmk6pxwWOOFdF1h9MAczl/auL
         XzsDlWv+l5+4bG0H2ATqG/RiA3n4zjoSTwrH6MeEvHj19iFlLQf2Kguo3xYgNrIHmX8M
         nHuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=rEPMMiUz;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id i14si260109ots.4.2021.03.31.09.34.52
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:34:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygBX+pimpGRg7b96AA--.53526S2;
	Thu, 01 Apr 2021 00:34:46 +0800 (CST)
Date: Thu, 1 Apr 2021 00:29:49 +0800
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
Subject: [PATCH v2 9/9] riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU
Message-ID: <20210401002949.2d501560@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygBX+pimpGRg7b96AA--.53526S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFy3Cw48Cr4DZw4DKF13CFg_yoW3ZrX_Ja
	yxJF9xur1rJaykCFZ2gr4fZr1jv3y8WF18uF1Y9ryUZa42gw13X3Zxt3Z5ZF15Zw13WF4x
	Z3yIqF4UGr1UWjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4AYjsxI4VWxJwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM2
	8CjxkF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAFwI0_Gr
	0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVW8JVW3JwCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU8PEf7
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=rEPMMiUz;       spf=pass
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

Now we can set ARCH_HAS_STRICT_MODULE_RWX for MMU riscv platforms, this
is good from security perspective.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 87d7b52f278f..9716be3674a2 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -28,6 +28,7 @@ config RISCV
 	select ARCH_HAS_SET_DIRECT_MAP
 	select ARCH_HAS_SET_MEMORY
 	select ARCH_HAS_STRICT_KERNEL_RWX if MMU
+	select ARCH_HAS_STRICT_MODULE_RWX if MMU
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_OPTIONAL_KERNEL_RWX_DEFAULT
 	select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002949.2d501560%40xhacker.
