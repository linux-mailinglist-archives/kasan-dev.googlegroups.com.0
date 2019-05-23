Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4O3TDTQKGQEIN6H5VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 91E2B2756B
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:54 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id 28sf4346651qtw.5
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588913; cv=pass;
        d=google.com; s=arc-20160816;
        b=I4v+YgsUSe6HbRgzGDMqaIgc8dBZZ989AIbqXoizd6pE1TqogSQAbMZ8rrq/nDkU1j
         HqIxDd8uB0kTXqtVWmVuZFwyWavy/mGc9jaXnDHyvNqDFBCN7NP/AzcYLBHsZDcJBROT
         zR1Si9Eg38vZxc8+w/Y9P/NJGp9cgpGdgibeB+ka3abOdV87JNoKfSEuEmx9EkPk+1gm
         6ssi9BJX9zO564kBCLryPwvxYMPb8d13SSScmjwzv8lW3/oMCTM3kqR0Hk6wQJ+i+C/V
         4k6YGwkpfPit+bCfZzMEYtSeK5+YwPhH+1PSAGCherSQ8nd+MV5qQCcO7zvV2pGyZI98
         zZZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EC9ZZ7iSQnkrhsx0P4wWLyyIzjfSu/E3eIdA62Z6djk=;
        b=IBNVaMJ5U6vld5cM5JMWBv/FlQ6f3SvF1SmCIjZUW1ZCmsgIfOmN6M11Qtyx28rO4w
         4ubo735xkQAr1klBVylPFmFYfJTA1crHAsX3X5JeYEJHfYoW3x4JRnOveCXMThCtnVTv
         bGFaFnDBch3GBLhsISkxWqizFLxlfVT/vi7xJt75SN2yuyfMTI7sJmRsqRHoFvTxny9u
         29jrUsfIj0aDOLjQ6jVq5f6PxyVX5JfGbtwiGLcOxi2i+EUaBrQwSgMxXdzCEntn1Ylo
         ePHQmKUz8ui70bfjyhJshkpOx5kw1pZev9T9mUbafOwZC+k3tTesnkNLnp2NrkUEB8sZ
         fsIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="FC/1eLi/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EC9ZZ7iSQnkrhsx0P4wWLyyIzjfSu/E3eIdA62Z6djk=;
        b=nY9sySGH+AwsTk5Q69K02dhMSglwIV/5D79jPEROfro5D1DnPUCBUTSpVldrYXINM9
         hZqeAqhlXyC5ZYU9xSEr3t/XGVC2sXEnQ/+OTwbqkHiNoyh8T0zMdqKuqmMKYsOKJt3N
         qtXRvVLkQDU8lN82HbvvtKp1lPoRCnwDkNjA3NhxYM9QqRTDwGJElVkpyVGmh/+/pOAt
         IfDjRl/YPNYk0sUtKbPio+WHKljTuy41kIAqt7CSEt3D+D8cknw1cT2Kufg85zitVmC/
         IcVvmJPVQ/0a6tnFQ3NciLkYw2PD7hC8XKMLo1VIr3fzBbxOm5P2bDeLIDpmaty8eEHV
         jYBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EC9ZZ7iSQnkrhsx0P4wWLyyIzjfSu/E3eIdA62Z6djk=;
        b=rgKsjmghS8fp+NUHOaXX9UFIKbFQoFuBqHcgrfp4uqQRBCj4bMw7DUdOTox/WHWI84
         z5k3NVrsUYzMNrgONjBFrbRa74zIyIzsFJ6lHpey59sWFZvPp7WQcBVwk6jos2eriiDL
         wO11dCN55aVdOjBW7x6FS13WCykAiXkuknSqqhp0H+GzlEH2ELAoImkMOS/e9MEeEo65
         r+DzEDDde4OB9BAtEGrpaGaYYUfPrPEdyvftGuRBIhdk4BXvzVehIkA/TsFKOHBewQgk
         RLmLPYjzlLDvxKJETbeU4aXmTe60reHK8WevMF+3tHV2I6oatpvXks4F2s6eZxq2XOvM
         ecsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVR+YqaJxbnKir3kGWMr5rWiu3x8yU90tixvTihzGJMKxpcHw49
	ypEK8HALZltFTHYTmLRm3wo=
X-Google-Smtp-Source: APXvYqxP0Lh59/Kp0kgiNJ/BNF9S0uBvdeX7J19TgqE5F8zDSspIhPI4SXF+P2tl4QOdu+znb4YpqA==
X-Received: by 2002:ac8:3658:: with SMTP id n24mr79124753qtb.354.1558588913565;
        Wed, 22 May 2019 22:21:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e611:: with SMTP id z17ls902660qvm.5.gmail; Wed, 22 May
 2019 22:21:53 -0700 (PDT)
X-Received: by 2002:a0c:d23d:: with SMTP id m58mr58103217qvh.210.1558588913346;
        Wed, 22 May 2019 22:21:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588913; cv=none;
        d=google.com; s=arc-20160816;
        b=DfMbCqzTSTsixnjj38E3iNKQ5+4qhHggRFBovYGy9SNooWWwv4RUrPit+GJaABYoD4
         YEiDXF5SrRVMdzH+VDoqPDoyAkd4pFjwBXGE8PbiihMS83rPoWEu77WmIuWVDymLKTQv
         cctWiEtVIeJGxaXO9rpN3J+vKAwMm+XD9CCuXDFEjfhdscAYc5qYar6SXj0XKNZ6VBwB
         LT+gI9uZbOwk+LKoB6Oy7lpKHqBT8+l0/BeVwsGut1LHxekQkngmD2Oi02aSRiO4SkVL
         w4z7mdII06u69MKSYUdIX1/1w7wI6dXxcR3YrNNmZhMihZTwNaPWIlmI1lVFaCtOA4UK
         dNAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lt/f0ObyN7xCbtUHCzfr3dU/UK0qK8L02lIHfhPrE+c=;
        b=i4QSA6hljPnzMLwWKQL15egDPBwAWuK/GmayPv9epwwoWNTf3cX08ZmkP/7eDPGNqQ
         pHxuRntY5/GyKkUDbssAoVgV543UIjppsasfCRGZP7vITS93OUEcnY03zUVuijWxB7iA
         P8HUu17V/H8i0Z1VI+OuLPAj3OgEGckYtUaBP8uTgheVmV8MDh5Et7Kjq/oq71mkxwUV
         CdTf/ES6q/li3Y2e7maiAdIqWadP0XIwMp6vKOkP191TcCNxVyKOoXHRMR834EFMnR/0
         CIQVwL8RLyOwEPpujEN6cyJEcMgd9C8a6ctwWaV9o+REmvIBuv8x+MMoQGFV2wnGmArp
         0ewA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="FC/1eLi/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 45si1709718qtq.4.2019.05.22.22.21.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id t1so2493158pgc.2
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:53 -0700 (PDT)
X-Received: by 2002:aa7:87ca:: with SMTP id i10mr74893088pfo.157.1558588912980;
        Wed, 22 May 2019 22:21:52 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id h5sm15236829pfk.163.2019.05.22.22.21.51
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:52 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 6/7] kasan: allow arches to hook into global registration
Date: Thu, 23 May 2019 15:21:19 +1000
Message-Id: <20190523052120.18459-7-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="FC/1eLi/";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Not all arches have a specific space carved out for modules -
some, such as powerpc, just use regular vmalloc space. Therefore,
globals in these modules cannot be backed by real shadow memory.

In order to allow arches to perform this check, add a hook.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 5 +++++
 mm/kasan/generic.c    | 3 +++
 2 files changed, 8 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dfee2b42d799..4752749e4797 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -18,6 +18,11 @@ struct task_struct;
 static inline bool kasan_arch_is_ready(void)	{ return true; }
 #endif
 
+#ifndef kasan_arch_can_register_global
+static inline bool kasan_arch_can_register_global(const void * addr)	{ return true; }
+#endif
+
+
 #ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 0336f31bbae3..935b06f659a0 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -208,6 +208,9 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
 
+	if (!kasan_arch_can_register_global(global->beg))
+		return;
+
 	kasan_unpoison_shadow(global->beg, global->size);
 
 	kasan_poison_shadow(global->beg + aligned_size,
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-7-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
