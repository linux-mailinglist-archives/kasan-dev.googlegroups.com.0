Return-Path: <kasan-dev+bncBAABBWORWKDAMGQEI2UPOLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F45C3ACD1D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 16:08:26 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d12-20020ac8668c0000b0290246e35b30f8sf4763646qtp.21
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 07:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624025305; cv=pass;
        d=google.com; s=arc-20160816;
        b=uQ623+2Z+lfSc229tGov2ErWuAzfs5cXhPMj0JRnBRgimlFkfTViaSa2J+5YQ5ojjZ
         hBjHUbiHP0sozyQ0mSdgRtf3hqrQ03siMmBUOdJ/Un1oEscoiZfNP0GWFgZZ0hm9jD4V
         nkRxz7g54XLjim069C1sGK+wJimrbbkXFSS2wsI1zq+JaAyN5wuY2bcycNxd4M9ZI8k4
         6L9a0bRoqcusZehK2WZYkjR840XYb9cWIPwmWBi+O6brjjr/ypmWHC9MxjjlrCXvurVW
         rnOiLptroBbjlEEWry4NmHt17238A9cRuqZvVKF16DQmV9KNS61JOVN8XfBbJNl3eVfj
         b1eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vZw3AW/ED/7LIWdZ6Jtb7rVyitQq63TEVfd5/DcKuzE=;
        b=Z87bUjbPQvURRQhCaeSWLObKWPWljD4BSYHf64VLkKW9r4LO7H066RfPduNFvz1hrM
         lL71+3Z2EAAKEaLVmDkt01G7cDVjbXRqaAK7o3/CP/s4Eb67fOmkkUnd63JYfSATabCE
         Ltmuxvk2YL+yF7DccMApjOjipvo8dssPt1YfX9rD/qSdGZu/RV2xQsAeKTIwV7KyiQOp
         q7vErBr81Ms6UbtqvmI0ItU65eF2wIYJh5L6tuT9q3EE4GO4/3hX6BxsDFwQbjlBhum/
         Ps4sCmmAGFgmoq2BU4Ld1wqbM2aAI66HR+md6fm9BSWRLFz12VTCg8SWHOjWjlCRaNry
         84Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=KfvNmLF8;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vZw3AW/ED/7LIWdZ6Jtb7rVyitQq63TEVfd5/DcKuzE=;
        b=PGu+Ms2IRCGLIAdmyobCaxsuXVs8FFg9nnTyrqVe6L0gEoWftCXSEeFutaygwquKjO
         kEn3S5Anq9veh606/WdX+uRMiCSr2HuXRhoGelL0XbcViJ4T+opFqZ+7jOZZ8d9VTC9r
         1IfiEieNR96sFWsODiXWY/3ca17icvkdBmIWQU3k4zpC4ETYwRmclXv4NCKFY8NXSFel
         KQHDyMRsyia3KjGAR3zgmJkySxa6MHLZo0ISCtsJi6cHvg8Or36tYiVo134GPf+hr5AS
         yVlVsK2kWMgqfGJQ3XXk9wzb4HjFv88y4ieKeR2yJDqxrTu199+0lKVNhEyybZ1yLMU+
         Rdsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vZw3AW/ED/7LIWdZ6Jtb7rVyitQq63TEVfd5/DcKuzE=;
        b=e/GAyji7nrLZU0aUNNuiDpPaAmyXJ1QgR9HBsCBGckmMIbvGzZvwTf0feeccbhw81b
         mY7IAcTdX7HTHJ3oSGe1lp2SagNYzyT/FjbyTNtQqQAe3izXgDMigPS/G9oDdZxsPwmM
         6+ijoNSjsPGiiubYRLmzFL2H3/DMFKozy2E16RYrtZ0+OpDvezXvcoC7RmU4RohdXENP
         Szg2I9yXKYGqrvvISFBVnm6D3u7K/Mp5eP+4e88BJxqAD4bqd8Onw5rh1VtVlYCCHIFt
         xxLTlQPA9j/cr4XA8PN4wgzXJ5Z1YJGxLJIxqQCvU/MzUZWMYjrX6KWqh+X6Kxg6yR5T
         IH5g==
X-Gm-Message-State: AOAM531cSPnq8aFdClnejWfmPGbvLEwo0+AxFjGSUrPFbC5k1Mn7V3E5
	ZWlGq9xW8zPyQsiRA3dCh28=
X-Google-Smtp-Source: ABdhPJxWdzBrODIm3jXYhrlos7emtz+gAQ1+rgqpFNAIKplE1Yqd+KtMUZz/gyWggYu3wI0m4UcynA==
X-Received: by 2002:ac8:7457:: with SMTP id h23mr10641106qtr.344.1624025305547;
        Fri, 18 Jun 2021 07:08:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e407:: with SMTP id q7ls6956668qkc.9.gmail; Fri, 18 Jun
 2021 07:08:24 -0700 (PDT)
X-Received: by 2002:a37:7b43:: with SMTP id w64mr7764406qkc.94.1624025304702;
        Fri, 18 Jun 2021 07:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624025304; cv=none;
        d=google.com; s=arc-20160816;
        b=V06u0lLky+yyni0BDvRPNIYjEXJLtrceu0sP3JMYVDej1JmV2ZIrkOxVyKue2EsOcN
         OJZGUeutH88xRV2dccuv279+1g6cPZDft+isY2u8XH7LL1difXPgswwPaQj3IwhVVBJa
         eZ/QU+QdEmOZT76vnGXNFdMfibPlMr6N86HJjIiglERF3l/hl44EQuTRODBX7LUssmcc
         JMB6aKKw7ZzxUi397ZS6TcO9vzndUSsBBfb6Xhsh0AhGX8xnDtZ4Im/GZ1Y0qq8rmUll
         0rVDR3MKa8KGAPrchoHGppHeSEeDxLQ+B2oiTyr612vydFXlpuIQf4N/flETvnYpSNUi
         QZPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=6URVM7kwZFYoTQ0Jt4HvPCFsmhETjeMSlkHESOmiSxc=;
        b=f7qtZ7GesxehpOPCD2Ekc2gDQRZUewegLklxjLg9MTKAjILtxnsFhaKVtCzXCOVhA3
         rAKTu/OuBtz3kk+Uito3hbs/2gYB0lWnEfUj8u/mwRIOAH+iOaJYwND11SWgjQm3DzOY
         3/i8XXLYVMUelTur9bdoVff8zqyPX5J6BVP28YhXTjBoR9oPMIyBdV37JqLTH9MSGRxG
         maITygxnOvAnTsHZvJg5vpbAFUqoIjLXuTjQuurumKeXQqof+TEcXv1Od+MDYyKJ/M9Z
         H4ag47xYmHH6MdTkEQSDfUR6sY1LNXT+SvTv3Anj7rIe8Bqfe7xvr3mHWNmgV+VBkjHg
         CZAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=KfvNmLF8;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id d11si577064qkn.2.2021.06.18.07.08.23
        for <kasan-dev@googlegroups.com>;
        Fri, 18 Jun 2021 07:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCHj1uTqMxgX_3+AA--.51710S2;
	Fri, 18 Jun 2021 22:07:15 +0800 (CST)
Date: Fri, 18 Jun 2021 22:01:36 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, Palmer
 Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Alexandre
 Ghiti <alex@ghiti.fr>
Cc: kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org
Subject: [PATCH] riscv: kasan: Fix MODULES_VADDR evaluation due to local
 variables' name
Message-ID: <20210618220136.21f32b98@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCHj1uTqMxgX_3+AA--.51710S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxtr18WFW5Kw17Cw18Grg_yoW8Wry3pr
	WDtF4rJrW5ZrsYgasrK34j9F1UJ3Z2ya4fJr1UAan8Aa98Crs0qrn8uFZ8ZryjgFWxu3WF
	yw4Fyry7Wr12y37anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkmb7Iv0xC_KF4lb4IE77IF4wAFF20E14v26r4j6ryUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Cr0_Gr1UM28EF7xvwVC2z280aVAFwI0_GcCE3s1l84ACjcxK6I
	8E87Iv6xkF7I0E14v26rxl6s0DM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI
	64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJVW8Jw
	Am72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkIwI1l
	42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJV
	WUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAK
	I48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r4j6F
	4UMIIF0xvE42xK8VAvwI8IcIk0rVWrZr1j6s0DMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF
	0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxU2xR6UUUUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=KfvNmLF8;       spf=pass
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

commit 2bfc6cd81bd1 ("riscv: Move kernel mapping outside of linear
mapping") makes use of MODULES_VADDR to populate kernel, BPF, modules
mapping. Currently, MODULES_VADDR is defined as below for RV64:

| #define MODULES_VADDR   (PFN_ALIGN((unsigned long)&_end) - SZ_2G)

But kasan_init() has two local variables which are also named as _start,
_end, so MODULES_VADDR is evaluated with the local variable _end
rather than the global "_end" as we expected. Fix this issue by
renaming the two local variables.

Fixes: 2bfc6cd81bd1 ("riscv: Move kernel mapping outside of linear mapping")
Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/mm/kasan_init.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 55c113345460..d7189c8714a9 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -169,7 +169,7 @@ static void __init kasan_shallow_populate(void *start, void *end)
 
 void __init kasan_init(void)
 {
-	phys_addr_t _start, _end;
+	phys_addr_t p_start, p_end;
 	u64 i;
 
 	/*
@@ -189,9 +189,9 @@ void __init kasan_init(void)
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	/* Populate the linear mapping */
-	for_each_mem_range(i, &_start, &_end) {
-		void *start = (void *)__va(_start);
-		void *end = (void *)__va(_end);
+	for_each_mem_range(i, &p_start, &p_end) {
+		void *start = (void *)__va(p_start);
+		void *end = (void *)__va(p_end);
 
 		if (start >= end)
 			break;
-- 
2.32.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210618220136.21f32b98%40xhacker.
