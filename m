Return-Path: <kasan-dev+bncBCXKTJ63SAARBOPWTKJAMGQEE6BI5WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 65F0B4EE9E4
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 10:43:38 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id mm20-20020a170906cc5400b006dfec7725f3sf1200622ejb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 01:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648802618; cv=pass;
        d=google.com; s=arc-20160816;
        b=a9Iz+JHLB1Xg0BdWmaq2N5CcSbzQGpe4RPEhUvEOMgqyDl7ZpbY8j5eqIdynHn7MtB
         ULN7gtvQHWgnv1RKOUnUhe8GFZ3S5kijDALP/u/T5nJqlH3vkZwr9rO5wav2D8v0uFAK
         dAJfnmOEtZJ34mRMtDjShZoc+Hu85zmrf5TbMy9oXavd5pOrN+LXUEz545phc3KkebZo
         e5DdCiZYC/lesBnM7hmrr7LJobGP8RyeW2sWANkgEtIB+iFIkUZb369Zbu2HCAK6QUt2
         Bs038Ulf3BMu7SNEjvL/f7I8civqvLJnnKFlY1xuZ9+d/AF2/5UzvVLGdeSZsxzRwYxm
         lmUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=bbmk5UFN4+2txrnmwuLLLAxUP9M1mS4OdRdiK7llMU4=;
        b=g4J4+yoDLwZMHgChfvJaq9GrVtPYwus+HHyj/p23wl9E1aulnp0To6qwCSlOW/h7tN
         tvXGoGLhpbHKdUbHM7yqz2Z3kXPt/6VRyainNaji8JOh0pNVez5wFW21W+5OYf6ySARQ
         gpmezKjWVX/sA31ErPq+jfHpDJXBy8ye3Wp/O7QvNhAWhU06sCGb2bPEt70tE9gSCLto
         gUbhO9ZXK3YyH0XW7hps3oXJApvZ29MyN72OltKHF06lvvhLgm6eiPizffND9lFTRytQ
         eSE+W1YUzEa3XkfPPcbr7gLDrOi+27az5K26Iu6sXY9yd5P0lJRE4BJNkmOCagdlKw1l
         HaTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NBeky6Jc;
       spf=pass (google.com: domain of 3oltgygykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OLtGYgYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bbmk5UFN4+2txrnmwuLLLAxUP9M1mS4OdRdiK7llMU4=;
        b=EodM2WvZMHU/m7msYAJmjEbPFoKeEUrTqTB/cUNKiYCtmyf5ZgX1Nx1idz4NraJMY4
         uJpxKYOE6Pe7qdHFgbxbeCmpo1Z4W7rIIiHhu/iMAJC0Q5857eqEXDjdfhAvpmm8ZS/5
         fG9vHckGyKxLH1OdC+67S/r0xwtlspfb+mrhUZu4Pg4VW5qz+ICz5+Wv83D+lLTEN6Ya
         p2FTUVoJMPz4qSba6o4DLkkOMS7mKjUlG9dpVS1DiZgh/+bzt2OgbHzOfk6zqnpU/Tsf
         uc6DWG4AUCL+GrsGhk4ZGcR1kSawb6tjTS+nQHURuHpxI7f5kV0kiwSGD1fXCVDnh60g
         DSzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bbmk5UFN4+2txrnmwuLLLAxUP9M1mS4OdRdiK7llMU4=;
        b=IOuanYdIup3GbZPrkILtWYwsCMXchzgwhOeANlkIt17KWP92puDEOuMVwUBDLnI8k5
         IHk2Ds/NnRkCNgya1QE3m6+pmz//ucMROMX+Vtu018p+DvOUwVDy1oLaiBhgNdLg5S/o
         /BeJUX8ZO4r84UPiDafVsIj3rW6TTNlG4k29IOCH4sgNalLgihGbc8S84lvK4UEqKhEK
         VX093UrX+5Xp3rwgntLmLzPAoPNP0XwKczBW08H+c992nsUoPY2AjRlywNgOUuHJn85U
         Uy0PzRgs0wUxwLcAvNtwxIbRCfRklG3VUuCBe6OUVh7jwnIhUYn+6DrimVksrr7u3Hto
         bCqg==
X-Gm-Message-State: AOAM533ROK7IPOHYrM2D54X4eFraWmp2C4k+QaMnBfIPdVjizn1Olt2W
	0q6WpvgJ6DdSbDu3fY9GTyg=
X-Google-Smtp-Source: ABdhPJxIrN2OxCzgWyJJUfJUgN3MFVF3k5063616Fa3Vj094tdpWKiHUiTJk+TKaZa0FO5RtBIMpng==
X-Received: by 2002:a05:6402:14b:b0:418:d06e:5d38 with SMTP id s11-20020a056402014b00b00418d06e5d38mr19885858edu.90.1648802618014;
        Fri, 01 Apr 2022 01:43:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3f0d:b0:6df:c7a8:9684 with SMTP id
 hq13-20020a1709073f0d00b006dfc7a89684ls453428ejc.1.gmail; Fri, 01 Apr 2022
 01:43:37 -0700 (PDT)
X-Received: by 2002:a17:906:dc95:b0:6df:d2cf:4d93 with SMTP id cs21-20020a170906dc9500b006dfd2cf4d93mr8235112ejc.66.1648802617025;
        Fri, 01 Apr 2022 01:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648802617; cv=none;
        d=google.com; s=arc-20160816;
        b=HSNxqaDJE3s7Jg9RqSdxwtu52KvXjo9ULepNqtVEOtbzkjykJbqj292IQV3l206i91
         +n1BoJx+tef9eqvlxI0k3btNWjdMxNluB9jxOijf1XKvsh198xv9BCiSz/t97BvDJKe1
         U2gYrTZklI4fgxKHH1Baa2sIu0EjPoRw/mXNoUZA36LHr+BGWeYcH19IROOOVzH+GEgj
         UJfjqRo+e/jTHzEEU5ZQ8uM1ck9aroKyDVtLA3rFEjLCPDBSh0/8Ud4XDlgcpZtCFRhx
         B2C3Vipe02bKPXT4lC+Ao+qngpkusvv5acFwLXr9nH2w/ETMT8eyEYkQA94tibrMVmGT
         VZjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=cRmPyw1GBLL8aytQSQtFb31y0EvOTxlHrPZR5cT2j5s=;
        b=tyI7d1HKMmAAfmgBvS6tk6JfkTkzhXdCGKEPuEqS6taUsVICKtZnjDZgCsAIGhjvvS
         pFra3UV3BGSPSTWUpVPRjUPF25ni26b5ewpHLM5lKVVKBKRJl5j0w0bxaliyGIdtRpRm
         xzX0DlnHy+WDtU80W1BfE6LfXM8sG0EQomFaGohwga0vczdCbwtaZg86vbxrk1ub2urC
         mymFMCBlt7YiB2YrMsqAG8re+/SSS/EMqBkBDLZj7Y78TceTNMMu5lzFOeT684FyYDqx
         J/1xm2NGiiHUU0gbd4P8wLRylHGJLiSfi6aPI1evzDayR0yuS0Vx1PW2MEIVlOV7qiJw
         geAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NBeky6Jc;
       spf=pass (google.com: domain of 3oltgygykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OLtGYgYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id d24-20020a50fb18000000b00415e600c761si141932edq.2.2022.04.01.01.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Apr 2022 01:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oltgygykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v191-20020a1cacc8000000b0038ce818d2efso911327wme.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Apr 2022 01:43:37 -0700 (PDT)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a5d:55c7:0:b0:204:5ff7:74e2 with SMTP id
 i7-20020a5d55c7000000b002045ff774e2mr6876908wrw.50.1648802616396; Fri, 01 Apr
 2022 01:43:36 -0700 (PDT)
Date: Fri,  1 Apr 2022 08:43:33 +0000
Message-Id: <20220401084333.85616-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.1094.g7c7d902a7c-goog
Subject: [PATCH v2] kcov: don't generate a warning on vm_insert_page()'s failure
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NBeky6Jc;       spf=pass
 (google.com: domain of 3oltgygykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OLtGYgYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

vm_insert_page()'s failure is not an unexpected condition, so don't do
WARN_ONCE() in such a case.

Instead, print a kernel message and just return an error code.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>

PATCH v2:
* Added a newline at the end of pr_warn_once().

PATCH v1: https://lkml.org/lkml/2022/3/31/909

---
 kernel/kcov.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 475524bd900a..b3732b210593 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	vma->vm_flags |= VM_DONTEXPAND;
 	for (off = 0; off < size; off += PAGE_SIZE) {
 		page = vmalloc_to_page(kcov->area + off);
-		if (vm_insert_page(vma, vma->vm_start + off, page))
-			WARN_ONCE(1, "vm_insert_page() failed");
+		res = vm_insert_page(vma, vma->vm_start + off, page);
+		if (res) {
+			pr_warn_once("kcov: vm_insert_page() failed\n");
+			return res;
+		}
 	}
 	return 0;
 exit:
-- 
2.35.1.1094.g7c7d902a7c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220401084333.85616-1-nogikh%40google.com.
