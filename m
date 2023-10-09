Return-Path: <kasan-dev+bncBAABBV63R2UQMGQE7W2LZOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 47CF07BD477
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 09:38:01 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-65b0249818dsf54915566d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 00:38:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696837080; cv=pass;
        d=google.com; s=arc-20160816;
        b=QuJRTau6OSAjYHEeSGVK4dZ6Vs74FsU2vqZmkUNlYoxTi15pImK/ytYpWXQYvxlneI
         IGDbmcmFCagIqX9v2EZTNn15diiOGBF/ssmQkM1K/7Qif6gfjY0Pb6/6T1dc6Kdqeuu/
         Qofa/IK8zsWnErcMNF6cNNpyGOJHGoDHtFWd3/Q/xYyGAUXz1Le/y1egAuxBMXA5ZYO8
         YCcVJaHfWaUOT7oW4TE0oB3aPvMDDdLUU41Z67qZwSWSQYwRKJITco9/v2otpFM4hMJR
         +ALsoRfTaxpBQOdbffB/uIMpTPD7rd48JmD3kyL47BcTSdD00IWDsfFA8qGB5n0laY2E
         mm1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=M4fKmCUCfAHzj5i/fPBsCiIQ1Uxa3wczYcxzDB1/5Wo=;
        fh=UUa214INRvT6woJl2gu/H63Do4CJQ7WgsfgQQcBaOyw=;
        b=GZPyH5Vai1lvHZ89XGkAuqJxsC25BA94rtiCvFbkCQhCX0cXfeAZ/dhghovH/FeMcy
         p7f07netxmAPnDIm2yy7mtvWR+80cJ2fS6RpkHcVaZBudE6uXolp5PIvhIEXqqhBnrFV
         UT2uXSGUY72UX1taNjiLpDj3qBQNmWmCE6AaMkQsgkK093xaPFtwByUEQNlJYxWxBmzX
         mpIOuZ5OkxqXWNifIZm1MetLHIj0bpFCcnb0kSHckn5juaIKF2SwwI0En5nDtQ1BLTIM
         jN+lcYY2G2YgbBKLdBARurP/qEvfsU7ujpl2k4dsgl1qFsHe4CxnBmOJiLxdxQ9rdUcw
         0CxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CVKhhfHi;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696837080; x=1697441880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M4fKmCUCfAHzj5i/fPBsCiIQ1Uxa3wczYcxzDB1/5Wo=;
        b=EvxAzM5WOWytrskZWxHzUTLF/OJa0gdR7r0+FwfDNchMoQXi04mc5ikuE0p15CmVVB
         OjxOza+xweTgonSZqwRdrN8QoPzevGpP5mw1jyMzQg295rdmCXBGbijTZOMDmA5sS7wn
         3vgEazAj6CrnnmcUlGFV2ds/yqhfGVvjje2oZ07k7q1RW2h4brv5/94UT2jFFdMwI2E/
         r+Ec/EEd/2ki2nkcrwUyHir/Z0bvo7iqdKQ8cZqjlx0Q6uG0P7+KKuCXxLHkBCn0JjAv
         42ENSC3eobvB8bysXQN6ZjdUVK1d9njvevikgeCUKtM9M8J20tVbE9i8CykoKlXHNNr+
         POFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696837080; x=1697441880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M4fKmCUCfAHzj5i/fPBsCiIQ1Uxa3wczYcxzDB1/5Wo=;
        b=WnJXK2xlCPKS4/nJG2bkpl1B8mX+VUeM9eIevVT8z8ryHnUUstakG0ioijIhzq3EGx
         5ytZGk4e5kAPUr3VnEKrw6ONvvTFKInHTFtOZNjN8qD6geNRTUCE4rbOt+KMRlkhBpO6
         fIKRP2ez98veQDk5FTZV/ZcFJaMqiyaqZw/si8zOYS7CpXwAdjaLI0se7E89DsA63U2K
         bsBvFKzueEXkYHVZP5yr9B5CkO9azEAb06NmR31jBP/3MDGno6wP4GGfEznJqnY1mOsK
         iprZowI/gwJDmQtCP19vU7BnceeGvtLMahEO1cV9Yq8TOd9czNUjtp0yhlg69bfbebrh
         KfoA==
X-Gm-Message-State: AOJu0YzstUjbZzuNzaXnuOQjr1+A4po+qQrcsCyCFZBxBjxoz9EHllJ5
	sQ8rCtiSKVvDkMA4rju767o=
X-Google-Smtp-Source: AGHT+IGYycG8byHIA8Qhh+SX3jqrnslrwK3WqKw2WuTKELSpTQ5eNunwhQT+yDk7ISqoxdTVETkrPA==
X-Received: by 2002:a0c:e48c:0:b0:65a:e57b:b511 with SMTP id n12-20020a0ce48c000000b0065ae57bb511mr13722211qvl.7.1696837079890;
        Mon, 09 Oct 2023 00:37:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e154:0:b0:65d:b9b:f308 with SMTP id c20-20020a0ce154000000b0065d0b9bf308ls2427463qvl.1.-pod-prod-04-us;
 Mon, 09 Oct 2023 00:37:59 -0700 (PDT)
X-Received: by 2002:a05:6102:1521:b0:457:5db5:ef98 with SMTP id f33-20020a056102152100b004575db5ef98mr6022851vsv.29.1696837078946;
        Mon, 09 Oct 2023 00:37:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696837078; cv=none;
        d=google.com; s=arc-20160816;
        b=dVOyVlElS7d0yo5wmA0gJfVvIwit5BPfo+I9g3y9im6WsIEo1vDAMI5T8cq3YaiFx8
         IFZjwsBnmn/RDZ3tYrP5WkVscmm8cPWc7SC6rjW4eMCs9tb+3nfn1lrFvlaWqicFc19O
         vGMRx+PhBzI8ldjO5iPbjSnliMQTQZBbLlcXxAPDKgLV/rVq+1//Cq5LeyB07GEyKCOw
         sCF/fPqRZ710zAF5iCtkagIaJXKuls/8ldkGbqbS/JVml0gX8YWjzcwWyp9laIr8zGk6
         wsrTNnhNjI/C/yAhLeagrn/iK5NfrK1Lw0pu/AIreLYVY9iGxlEWJOUXB3bj/y5yxGmS
         i79Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Pvei1ks/khlX8BXIzq4Y8G7n7B36rJvutKNZiv35fU8=;
        fh=UUa214INRvT6woJl2gu/H63Do4CJQ7WgsfgQQcBaOyw=;
        b=gm40MGuixssFEG5vYkfmexDKTwG+mvLudv31O4mQtIaoVOdzM+DPcQAtAfo3tn/Z0k
         fiikUmhvHK9mjRk7dUqaHkTeOFjBu7z0iysxoSYmVxhYpVmrbZmTGJKOjKvCF5RMfJz0
         JqhmiO3RJXPk57hSwH1Szzj6PW9jdZeHmHSqc0nUHHErWuzQaQuRpmusWK0foSVGIiQd
         LVPJud6a37/KopaYVjiiZTXyXureX4RC3OA7rksUuBn2vuLuWX1GzoxruWd6VvqMNAHI
         rBPGXEFv1ahTElVt524Mpw3nS/R/o9lrfiXn2T1nlkmVHDxCPcSbPRCBW7BoNBKlHnuR
         +U6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CVKhhfHi;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id ay28-20020a056130031c00b007a6109a9b8esi631224uab.0.2023.10.09.00.37.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Oct 2023 00:37:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: c0a30056667611eea33bb35ae8d461a2-20231009
X-CID-CACHE: Type:Local,Time:202310091533+08,HitQuantity:2
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.32,REQID:9af3af66-440b-46d0-b12c-57bc05c1f702,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:5f78ec9,CLOUDID:9e6dbabf-14cc-44ca-b657-2d2783296e72,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:
	NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: c0a30056667611eea33bb35ae8d461a2-20231009
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 93459825; Mon, 09 Oct 2023 15:37:51 +0800
Received: from mtkmbs13n2.mediatek.inc (172.21.101.108) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 9 Oct 2023 15:37:50 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs13n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 9 Oct 2023 15:37:50 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <xiaoming.yu@mediatek.com>, Haibo Li
	<haibo.li@mediatek.com>
Subject: [PATCH v2] kasan:print the original fault addr when access invalid shadow
Date: Mon, 9 Oct 2023 15:37:48 +0800
Message-ID: <20231009073748.159228-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--11.043300-8.000000
X-TMASE-MatchedRID: vb/S/ihWjLk3hN8xy8q7MnQIOMndeKgEMApqy5cfknVXPwnnY5XL5Mla
	v/so0mjiO51tDCZfaDqmvurnuvPUoT9WWWmKWtUYSHCU59h5KrEBmf/gD11vZI9x3aMQAmDtFTf
	B1yBPlPICwWUI3NaNHbRCpOgpqZeg9BhkkEGgXxGzI1v7J4hECko8jH4wkX2j31GU/N5W5BC4Nj
	3Kc7xHIlgw2yKNObv1gO92fqQQImpcPJ5MOmncJgwfhKwa9GwDfS0Ip2eEHnz3IzXlXlpamPoLR
	4+zsDTtviI7BBDiM2KwfWryaaWDXBKZmjqY1lnK7Ipy5jxIfwR5XDkPsW+gWg==
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--11.043300-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: EE42831E05BD0403DB997D7B3FD28C9A3D60B62DA7DC7C0632785B74A443CFC22000:8
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=CVKhhfHi;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

when the checked address is illegal,the corresponding shadow address
from kasan_mem_to_shadow may have no mapping in mmu table.
Access such shadow address causes kernel oops.
Here is a sample about oops on arm64(VA 39bit) 
with KASAN_SW_TAGS and KASAN_OUTLINE on:

[ffffffb80aaaaaaa] pgd=000000005d3ce003, p4d=000000005d3ce003,
    pud=000000005d3ce003, pmd=0000000000000000
Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
Modules linked in:
CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : __hwasan_load8_noabort+0x5c/0x90
lr : do_ib_ob+0xf4/0x110
ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
The problem is reading invalid shadow in kasan_check_range.

The generic kasan also has similar oops.

It only reports the shadow address which causes oops but not
the original address.

Commit 2f004eea0fc8("x86/kasan: Print original address on #GP")
introduce to kasan_non_canonical_hook but limit it to KASAN_INLINE.

This patch extends it to KASAN_OUTLINE mode.

Signed-off-by: Haibo Li <haibo.li@mediatek.com>
---
v2:
- In view of the possible perf impact by checking shadow address,change 
   to use kasan_non_canonical_hook as it works after oops.
---
 include/linux/kasan.h | 6 +++---
 mm/kasan/report.c     | 4 +---
 2 files changed, 4 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 3df5499f7936..a707ee8b19ce 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -466,10 +466,10 @@ static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-#ifdef CONFIG_KASAN_INLINE
+#ifdef CONFIG_KASAN
 void kasan_non_canonical_hook(unsigned long addr);
-#else /* CONFIG_KASAN_INLINE */
+#else /* CONFIG_KASAN */
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
-#endif /* CONFIG_KASAN_INLINE */
+#endif /* CONFIG_KASAN */
 
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ca4b6ff080a6..3974e4549c3e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -621,9 +621,8 @@ void kasan_report_async(void)
 }
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-#ifdef CONFIG_KASAN_INLINE
 /*
- * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
+ * With CONFIG_KASAN, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
  * before the actual access. For addresses in the low canonical half of the
  * address space, as well as most non-canonical addresses, that out-of-bounds
@@ -659,4 +658,3 @@ void kasan_non_canonical_hook(unsigned long addr)
 	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
 		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
 }
-#endif
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231009073748.159228-1-haibo.li%40mediatek.com.
