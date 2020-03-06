Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUNCRHZQKGQEQ7POAUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DD3017BEE0
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 14:34:10 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id c13sf1301484qtq.23
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 05:34:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583501649; cv=pass;
        d=google.com; s=arc-20160816;
        b=eBUQCRl1suA9zV/IVNaSRMP/NnvppxBW/dTLOruWP+EkPSCwO2FryNwQsnDFmlv5i3
         9S74GYnVyGWX2M+qs+1vakC7e/gxoXim9rlXcuYbalegp3K2pYnaHAwYHwAxPGu+iPF6
         fAux3MkHxt/bQ0xapThvJ/WMjriSnXQKPTUgjhJySRG0lCUOKQhOZIxOqnu3XtvYyoe+
         VDabvNdHFQTZM0spHOygY8/AiDioCrnqg6+ulrK/ozDFXE3fHrw6AF5Iw6uVeltGROc0
         FlPPK+D2MATnR3jxhWjZspHcg6KFz9HxGmHWeuznMgAyCz/npaHjgQNho0LpQWaDuUO3
         WURw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6cNxICi5MFUPxG1uEW6mkChRl1fQus1+7JzIi0hn3C8=;
        b=pDwUl8k8w1vDr/xwSqAfD9jzAkNRMNdk4LFvn/gJiyCPpk8eNwvf6uopNi9/cfNcuS
         cqyCoH/iQE6s0eM1ebzncV5vcqGBrrsibdXdaeDgT1woQ03sgtRqgB/nDPZjTdJdH+b5
         JuXy+VJNxIK841vJG6QPnj1pc6LIhxRjjGah4WIvEjcg3RlNlL3/9HTnmswFiT1ROReb
         cNaiD1LfXN7iTHqEtykyC7iECH+VBOtln3y6nZw+J9PytXnh4xcpdcy/ghrNJVJhX5ne
         LQFepNNqyCKWKM6fqQ22CiF+c7Xr2f2BtogCF0Kfsg+ygJI9eBZ/hq3vAyDYlzqyqTzC
         o2bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hqyTcqIG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cNxICi5MFUPxG1uEW6mkChRl1fQus1+7JzIi0hn3C8=;
        b=oJiP5cnJfIgyFEm4IEGFedIVs4BLicForZq155cM6R2hqdISj6H/CmWN2TpXIgb4+4
         YahMrf2Z+3GKpSIikgTygyAO8i42dgZX+MT9di1gmZkbuuDwq8Ji64XgdICf2VwcTUNJ
         L+CtMsORB7ZEH+2MUhLdr8D2qXBYIhJyghzlovz1XfanU5MAj6BhGp4EF3YdJh2gzOMN
         ApjzTzns0A4QuVPslS5qMQhLsau382wtD1yYWPxOvd8qYtBn3raN8PplLlWYTQ4OIp6l
         9feoF3TS2gJZTc44BOWncL5IVlTtCkzFpVhKWrDVhlW2auh2iHZM7JYj66X8LUTPUWn8
         EXrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cNxICi5MFUPxG1uEW6mkChRl1fQus1+7JzIi0hn3C8=;
        b=MmFT+m94CkGaC7WGO9tA44vx0MHfvjz5bg5bjODMyedorP4h5EnrJr353Y01LzhrnA
         216U4EaPuQAlbsVflAyhA/U+kPKt7s0nXpbDmvk0qrRUa9eeGleUKgTyYPOF3iSeVgjq
         E8BGg3BmF0XYXybAFB1kDbftql2c76VaoRcvkAfhlS6BGkibnrWeHcBB3iq/jabQyt2L
         1z52I+SkRtUuLQFkXHrlXWEBfmYT5wvTXZQydys3LISRYibQAlINvZ/8uCaikTwiwmn1
         wkv5MGeQHAoIDfrqDA9ZvoYaD0QPhpsopAS51jnxLX1RMxaatVa0Z+pLsDKeZGdit8vz
         eooA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2ibu4sPRhhvlMm3JK6BlS5Fmdos+n7zLL5/JKm+cxOyo5oP0It
	3Uyd8A2KPH39zk58qKL1C7k=
X-Google-Smtp-Source: ADFU+vulciJrKmhTTufTRaRLmruNUy9qySndtql0ehXwAgdBoVzLGcUpcICrujeAKyNogMHFzxfEuA==
X-Received: by 2002:a05:620a:a94:: with SMTP id v20mr2824771qkg.153.1583501649176;
        Fri, 06 Mar 2020 05:34:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:42c4:: with SMTP id f4ls490745qvr.10.gmail; Fri, 06 Mar
 2020 05:34:08 -0800 (PST)
X-Received: by 2002:ad4:4a01:: with SMTP id m1mr2746741qvz.171.1583501648792;
        Fri, 06 Mar 2020 05:34:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583501648; cv=none;
        d=google.com; s=arc-20160816;
        b=VjWWNyZukG15tDz13HRWIpPXrgrwsepF9yjAf8ITpPfb7h9wbujPtGPcqebNu4M+hh
         wY6Zbw1avmcVh9BImRI4S6X07wh9L3cTNx5iV6jlVhJsQMJcrcydkVuySZ9Grjq9pC6R
         Txs0U1+/EF+WhXKI0GlU6vkJmkMzF9qfdGPera6F5Iw2BT01j/gWXEABCDm2y4cB+FBq
         Jvx08oHCDys9dkk++uvO9kRDh0thSMEgLxW9LzjIT2trZBUz5kQMSv0OzvR3T97m1Dgs
         EVdM+bqzWkNNHkFDXgE2TpX/tVTPFpPfC1SbdB+pxE+Z8cGJXdvAW9pk74SejR/N1jBR
         TVCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jwvqhmbLPpvanCf4CYPj6H756JJZayFM0Q320MsSZZo=;
        b=x1Jg1Df+7rwkeLXEOj5jf3RB182YG6JkK8knzJPqNZRKm8B6aOwrTd2YvqgU+zd6QT
         ylqUUIdVE5bMY24Ltq8ByTEtMi9tJk7/WlO4LmySXEzQstinPxfFU/0lxTGCLZT92PUu
         CmVyNpQKBDvY8DiVKaw5uDcQ0+x6FH+HMML2HN4BODzyWWJynNH/kLpzP4eTGCb8EsLV
         gkJ1H1Kt7FUiNTAdPVp6UWuoq1eUasFuIhFELjULvpVkDrEwW3GTiPc3r0RzBFs43imP
         SD8QChvxI8fScJZXW8nWltQ0DPcV6aMjn23ziA/HurLX4ODRKnm8PdXTkXcO1472KfjC
         APTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hqyTcqIG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id w10si123649qtn.1.2020.03.06.05.34.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 05:34:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id l41so1102904pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 05:34:08 -0800 (PST)
X-Received: by 2002:a17:90b:4c4d:: with SMTP id np13mr3730802pjb.58.1583501647865;
        Fri, 06 Mar 2020 05:34:07 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b120-f113-a8cb-35fd.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b120:f113:a8cb:35fd])
        by smtp.gmail.com with ESMTPSA id x11sm35601211pfn.53.2020.03.06.05.34.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 05:34:07 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Sat,  7 Mar 2020 00:33:39 +1100
Message-Id: <20200306133340.9181-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200306133340.9181-1-dja@axtens.net>
References: <20200306133340.9181-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=hqyTcqIG;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as
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

kasan is already implied by the directory name, we don't need to
repeat it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 6577897673dd..36a4e1b10b2d 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,4 +2,4 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200306133340.9181-4-dja%40axtens.net.
