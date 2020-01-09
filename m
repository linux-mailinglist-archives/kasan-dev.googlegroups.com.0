Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3VC3PYAKGQENXWJ2NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 12DFE135381
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 08:08:32 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id i8sf3153842pgs.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 23:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578553710; cv=pass;
        d=google.com; s=arc-20160816;
        b=nx5In+EAHCMyPKwAfNGc3bBODAFup7via5DkuHlvACXVb7LJKFxytwyVIYeiKoERQW
         d+DX4Qo7g/FYJE/cKU7Rph6vjecnWb/EJS/3k5w/fRrcMcTn3wQsqLyDPB0gd4q2AM+m
         yeqXnwwBq8txAnLOJjITIGUW4F18+UPM9il/midKJ73xw0AGGXOlkuiS0JfmbC/Us4c3
         9e3G1GlbHajIGkZRAgZSyc2pQD95cKObIqg7r+KjP/rdXICnz+Me+WSRpxfxUNTCrKUH
         SvqsJo3o9EQrL45sO4vMBbk4z7ADvsfuazavJgFPp3z3+TGWXEplcjXMJrrtKgd/gNGM
         5jYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jtS9rDQLW/gWGNkXlcg3O+8bHjpOuvnrRwc7ALndT7s=;
        b=t16+yVd2Ymu3MDYMNyl+vP5ukHz/WIif83jziii8+pKry2a73CsYTfuA/nMhuW7Q2r
         +0GprqLdMaKAZFll85cRVtbpYVFIVmCvm2lePcO+x6Zg4Y6FZ5Ve8wdQh76lyM87UZ6N
         SvYt1ZIiuEIuVXhDLdfHCGtfNJUxVOWHhM1homXD78152pxdroe/cm6rTi90DPBuO9oU
         euF5GzAQ/b++7A3e8tHeNhAMYkF7y/NaZJQti+LDNeM7x56R5WjQhDa0LOSU2PedPFjs
         bGCAmBDm0smbwskuKQ7fq7D6m/xXEvOGlyYne/Xoosxk3li/9AP+g2V+C4/tHGRTqez1
         JI2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TBrGHwgd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jtS9rDQLW/gWGNkXlcg3O+8bHjpOuvnrRwc7ALndT7s=;
        b=RUkyvdFnqygqwdD/QOAeziwkhpQ7iifaxgupmxmpQ3f0OYtsoTvg694amsKRBEfREg
         04XyTGN/Y54BhY+CGP4nqBjsr7KE+MkGCDdiz0oF4iqINC32Pv2kqiVYxMUsAjwiQN9O
         tI3PoYQW4xbe2VPUI7XJ6zPSwgcfZNCnEU6w8HX8E0+C0pTrLurzs/SFFz0xDtoOyD8P
         eYCprQEEEdo0EjBAmM6IXOttb9q5t6C9jPmCvhABQRxZvLNwSeEjMd6dTm30++hnN4ar
         hhbSfxjmXLYPtzETCEprV397zw07NbLR6jglTvQsUmEhFZ19IkK99H4g8LYpnNKClLpN
         hBpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jtS9rDQLW/gWGNkXlcg3O+8bHjpOuvnrRwc7ALndT7s=;
        b=VSMdgOVNUOzvnFyzsOAhMvwz8fHOUH0bqoFzgKsrxza67kmdzdtPdgUa3oyLZrIj8g
         5tUZZK2ccWHbwVBeyzEZhGY9eelWhWBqX0jn6qCiJc+K13cKa3TAjc8h/RHSD3LvxsZV
         Ssc1lCvicRVo6z9oV+KAf2ylfald4IAqf1gDS5nzywIwMmCe9u1zpItFVtrn6DEcTSZ7
         du2LfqlktzCs/nvu060JWqKE36d5ds6NmuDFObS3nMGKxGji6f2ZqCGcFvEpA0hnTORL
         i48ZwbRTbCVy+fPCtwOX6tuCQvDWk3Wd+50i2Fm+OBdmkRT6MFcmLSvHWcnKYQ64kx1r
         KqaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX0Nl1uqXtisww4UWgLqhmQPHDcXLxcLXKA8/q0yNwd8qd+DXUQ
	9/WCfbNg6mvIDoXup3Ck9Yo=
X-Google-Smtp-Source: APXvYqwz5WTpqSqBPh+YOy+jPJqmBg1eNLIkoQoOLPcFortrLPlLdvncf4qvf5CRNL5/CMsw7MZpJw==
X-Received: by 2002:a63:1c13:: with SMTP id c19mr9701722pgc.450.1578553710407;
        Wed, 08 Jan 2020 23:08:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad46:: with SMTP id w6ls373288pjv.4.gmail; Wed, 08
 Jan 2020 23:08:30 -0800 (PST)
X-Received: by 2002:a17:902:b08d:: with SMTP id p13mr10212561plr.109.1578553710004;
        Wed, 08 Jan 2020 23:08:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578553710; cv=none;
        d=google.com; s=arc-20160816;
        b=R2s4q4xAIyzsjkCTn8dfzH1hxSrZlON12NPrc9TCV2Q8zHbzAmz/NOnsXrTQ9hTzMk
         W1EaARuhWoAKL48eB4Hb+kqc3ZmH2HNHk2xcoatncV21l9RGS0ltPo13p9Hd82zGqVeZ
         ol/I4diCKXCbfsFZTHty1L0efyzITHxxlferVItdN3TW+QbLob/S8FTBKfw8he4tCPW8
         JYDpn6cSdYBKA19feouFBJ5RAQhRXxbUY4nqOtpupjer4Ypx+S9YC1rKpieFO+FGwJJG
         +qR6AbhTngSyWGPrca0T7RsvCaGWX3ujgo6O2c8suH5wCqJYIF1n8z/R8NCtcu6HPAQx
         yPvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jwvqhmbLPpvanCf4CYPj6H756JJZayFM0Q320MsSZZo=;
        b=rAoP+dzjwE9yi9dsdhdUF5rPAcBB5KmiZ5l/928ZG+/Y6nQiCBpg2qcwrCbhYkFOlZ
         1RanTVHvcIaUiOJrUdu5iiCgHREQAzqGd0EXQ52lh6bM2FPDtYXM3wwNO5lG66soI7cm
         YnwkZfud1IjXiGJxpbR85917ErbBwJVhDe3f4xLv1CEXOakI2cK2pIbEA4ynlXTLAui9
         k4XSv75SeSLy5dLcVUCqpxaGZDWgcgpR2qegt6t8KWDn9qmb81zfBOj1mm3Wh1w1tFpa
         /V6zvRJVSRLWy7G0zdxwUTxP0GSRoO6fYreuXNZo1J5oY8oTyutAzGZaunSo03CawYlv
         Fq+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TBrGHwgd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id x13si271469pgt.3.2020.01.08.23.08.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2020 23:08:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id az3so2174580plb.11
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2020 23:08:29 -0800 (PST)
X-Received: by 2002:a17:90a:3643:: with SMTP id s61mr3623176pjb.44.1578553709799;
        Wed, 08 Jan 2020 23:08:29 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-5cb3-ebc3-7dc6-a17b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:5cb3:ebc3:7dc6:a17b])
        by smtp.gmail.com with ESMTPSA id e2sm6363942pfh.84.2020.01.08.23.08.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2020 23:08:29 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v5 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Thu,  9 Jan 2020 18:08:10 +1100
Message-Id: <20200109070811.31169-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200109070811.31169-1-dja@axtens.net>
References: <20200109070811.31169-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TBrGHwgd;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109070811.31169-4-dja%40axtens.net.
