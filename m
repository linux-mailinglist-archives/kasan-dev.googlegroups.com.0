Return-Path: <kasan-dev+bncBDLKPY4HVQKBBIXAQOBAMGQEG7OS7UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9638E32D55B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:35:14 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id c7sf2839677wml.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:35:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614868514; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQV2uH3zQA3iFiLojCv29S7nKkOdNG3okvIBrg6lBUEO09O422aj+wefjVz78YzsZC
         J0ythAtWnPyzXFCftldlPHwbXr6JYmHF7B5GsIvL4O9Y2UC9Xl3Po78q4O9AkCA1s632
         wgphbevGW0jtaoWF3a0z33DJ0fj4WIJ5MLNr5Bq6IKqnAGdgpQkqYRkihZ1Nt9MRvH7J
         dgzQyy0ZnlBMsHK6YHi1TJaZmx8PRm5LOlSmIh9OsrYpWW+RUt1OrAwR0D7O/PrZ4EcD
         qTcyAyjHhnYLqBswYdNE5LnqyWfUGBqQu5ojBJYzGBGiowK3BmnP7yW5Gzzd5lO60cZY
         61ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:references
         :in-reply-to:message-id:mime-version:sender:dkim-signature;
        bh=lAtjFo8AFzFUGzs+BCYoPx3hNeOMiQQlZ+M8/MknNiM=;
        b=DFBnflKeExjWfWvzPe6pEMrjZpDV09/aDejPVowDMqBDYOjG7dKpj0FITU8cR0BT+T
         RTAtY2e5hbdyTZSAbjZcl3xtB3r7PntklDhLQxgNeolrUm1LlfhyjvJrPsR5owg6Qhw/
         /oIsWuJGDo+mQAuMHSEnNe1sLrUsjMTP/4mfqFhufn3ZhG4+F71ylvlbUtsuANanZicb
         1LSH/ukOHI4sirI2CiNVmg8Uj+otQ+vEUtyCesbLxZcunwmDEXXGCkvgXm8HwFlyffCp
         b5NA3+BXaCUA1F0uR5/mggB7eZcmznDxPmL7yToXHTsb0QJrk8pht3okOmbxFRGDiY0t
         6YtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:in-reply-to:references:from:subject
         :to:cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lAtjFo8AFzFUGzs+BCYoPx3hNeOMiQQlZ+M8/MknNiM=;
        b=WuGYDWpJmvCXm2Ob/+FcK2niKAwFhO1Qa3333J03o7Ua2xgYMyot5hOxLF31kqjAd5
         D8jQkK3cLVrlx49SZWPX7x+UWGB2O7hYxJ/ZQA9PENwPCLcMu1nYtHn8CQbruPyHCYCX
         ogtsRc7l0NvPdj39+m63xQ6vna5oQExLDj3iLb1NOLq4G+jax40h2Exyr/RTBsX1H0qb
         IpByWdvg7krTnsvWE84oFS+3vpJLoygyiNQSCzJhbjUc7A08fBz5LulbOpM/Q2rCJXGD
         eilphIdbThv7TFmexdSETIXlwikwiOkM7dzAGfjq4y/V/m4/xl85JPLyqCHc4i+LFw1S
         2WHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:in-reply-to
         :references:from:subject:to:cc:date:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lAtjFo8AFzFUGzs+BCYoPx3hNeOMiQQlZ+M8/MknNiM=;
        b=qeByQEQk3o/JXeXDD5uM/A93x0ZMhJYGUwno6G7MT/9mkRYzUzFslgNJfI7F/LtpNh
         AcD8gJXg0RKFIe7ICPG/POMISHoRR41g5/3fTGTk95NaGtxxXRzGqI/7Aqk4VuoDqW2J
         q1Xt3hcHYI6b4g4jDdJ11jReQIM/CApSEOQtaWOb8a8MfF5apLia6CqX6kb6Elnlon7C
         3hJKBsJMYOUYZaLNXsk5xd6JOezSsm1P0k/hS0BEF3t+MDn2dlMGOVZueI+1rPRNZ8H3
         6+PGPyuA6eDLeyjLqjnG+FlLATvBYViVyQisGc56amP0NbRulzljdorrWFDiSsBBudaQ
         5axQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OLGvA2C9Edg7DM8GPBd/lIverw5Y/p3vBAJ6oCScx9CxGEIC+
	nQFzrG/WZlDyYcwPAitBOEI=
X-Google-Smtp-Source: ABdhPJw1SGsNWntQ0hxTaMEmdhrwptMM++X7D32EDB9jjF/kZtRnNkDU4gIlOaBpd6jlZAndxHyAzQ==
X-Received: by 2002:a7b:cd81:: with SMTP id y1mr4316895wmj.51.1614868514416;
        Thu, 04 Mar 2021 06:35:14 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e6:: with SMTP id g6ls3739876wrd.3.gmail; Thu, 04 Mar
 2021 06:35:13 -0800 (PST)
X-Received: by 2002:adf:e5c4:: with SMTP id a4mr4393549wrn.174.1614868513585;
        Thu, 04 Mar 2021 06:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614868513; cv=none;
        d=google.com; s=arc-20160816;
        b=SMMCl/TyJQRAj+v5U4xO2j4AWscODf6Mg6ra45uAXodg9wK6uCJ5sstq4YHBRGI+5o
         jql1ClKhYFjIdr4KHNzs6UfcDq/beIDRTuvhtaveT0WUYl/tAOBkAYO2rjHoO2vHwExb
         PVwY5dzzi3OeG3b+/mP3eNq3NtC88vQ7mzchsiPv9FG4vaDy2Or2aYcwEoHCz0XQ0q5X
         FlivbEz3PnHnYbbspcWKJ2WfYl77fQ05EuWhCWlAIYHR9jaFihII/OyKV3Jfu+hL0vvP
         4f6z6XTGRiOVUttcazg2ekRklsOfYY3G8X0LAJX7KEZlBtiMcdqvrZrMBytk9526/jFw
         HGIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:references:in-reply-to:message-id;
        bh=WGy19dzK4120j4KG96It5eWnwHOEL3GZ/etNRCZ0k9g=;
        b=ly4Qy2dVAEFYvnzdWarFOP7E01x+sZdpv6X+avUjo49MCN5BSLQ7Z9j50QaiXsFUzB
         KQOv5vo9fLCdBbqWOTs4cjKb4Wpg38BtbwTdeQsbv8wRDjMvhfr90yERpMGclXnmwDp2
         AJ4gTkU/+G8RXEuj7X008MwZv5yX7f1af5lRRJb6jA6MHXhy6lObWIlqdcNdj0D9SupJ
         YykNYH4LgurNALSG5WYHX2ghaZAELnGjPhC61PRbQ+nBk8n835LFVLwI+oNkSB19ClBH
         hA23yaVLAxFoZ/Y2+H9gW7PmO/00oucoDnJjlBdedIU4wQmIMFoFQabF0vSBUkWEYTPd
         F0bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id g137si433231wmg.4.2021.03.04.06.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drtgg275KzB09ZV;
	Thu,  4 Mar 2021 15:35:11 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id I5IG9Wie4N1y; Thu,  4 Mar 2021 15:35:11 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drtgf6dfgzB09ZR;
	Thu,  4 Mar 2021 15:35:10 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id DD3BB8B813;
	Thu,  4 Mar 2021 15:35:12 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id VpKHhIzPqhYW; Thu,  4 Mar 2021 15:35:12 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3EC018B80A;
	Thu,  4 Mar 2021 15:35:12 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 1E721674E6; Thu,  4 Mar 2021 14:35:12 +0000 (UTC)
Message-Id: <678576e515573333c324fbc88cbc146e812dd9c8.1614868445.git.christophe.leroy@csgroup.eu>
In-Reply-To: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
References: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v2 3/4] powerpc/64s: Allow double call of
 kernel_[un]map_linear_page()
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Date: Thu,  4 Mar 2021 14:35:12 +0000 (UTC)
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

If the page is already mapped resp. already unmapped, bail out.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
v2: New
---
 arch/powerpc/mm/book3s64/hash_utils.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index f1b5a5f1d3a9..cb09a49be798 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -1944,6 +1944,9 @@ static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 	if (!vsid)
 		return;
 
+	if (linear_map_hash_slots[lmi] & 0x80)
+		return;
+
 	ret = hpte_insert_repeating(hash, vpn, __pa(vaddr), mode,
 				    HPTE_V_BOLTED,
 				    mmu_linear_psize, mmu_kernel_ssize);
@@ -1963,7 +1966,10 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 
 	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
 	spin_lock(&linear_map_hash_lock);
-	BUG_ON(!(linear_map_hash_slots[lmi] & 0x80));
+	if (!(linear_map_hash_slots[lmi] & 0x80)) {
+		spin_unlock(&linear_map_hash_lock);
+		return;
+	}
 	hidx = linear_map_hash_slots[lmi] & 0x7f;
 	linear_map_hash_slots[lmi] = 0;
 	spin_unlock(&linear_map_hash_lock);
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/678576e515573333c324fbc88cbc146e812dd9c8.1614868445.git.christophe.leroy%40csgroup.eu.
