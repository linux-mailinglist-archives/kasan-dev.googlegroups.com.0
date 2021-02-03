Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUFA5KAAMGQEXHKFLAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 22AEC30D960
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:00:18 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id z3sf15969786pfj.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:00:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353617; cv=pass;
        d=google.com; s=arc-20160816;
        b=f46AEEYYI6HHc3iJwFRktcQn6O7nftDtNYbW3tfSwGZQ9rxzLV/F/3FyP+JhYAUHmo
         NLJd+aX5LRAxK/oUPj43b6J9iL39x2zulR0I6gLvCc3nw4qBfafWkaCLTQ8aNG0HUXlM
         l2XCNbiMqL0q9D+3Gt+d0lXGyojKLJgMQlHWdsA5l08ax6+Suj1GbeSUDzxuTD3U5ApM
         YB6oa7sp4naAONmGDxWWIzs/tqn4S6jS119PZm6c9yRQfyKqH0+Oclu+NrmTfMhkbkqT
         98BiaEHdr47T8kuQV2gqxG9JkJ+TS4338aEsk7ue59v4Veg3Gw9TI5G23XfjRVVuT80N
         90SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XoWTe4b9O3y5R3RUij+hDcUvS+37vDuD2S492XD5S4s=;
        b=vWbs9+keJ0c+NG3xMJQxj/R5hfVEwGJxfQLP5Bux81Ki1gvPmqzq6Lpn2UaV5OqeBx
         1qFwLJPh0WHdgN/F4xUuXh6P/F7hg+/lbhqbeAJtPxfzUARcVQ7OEBmG2ds+eRl4dC1u
         bmWzlun4Sqp9o/Li6BDDywQkn+U4md4YtLhtiSGstgz8/LEFX4mCA/Dce0XvS4Q7O7Ur
         B9kTlYI6BrY8Scxq5Od03SI5lPqDRDWD2O17CoEftqG7dCnaTKjOIOESAK0KLX35j2CI
         51C4aFZocMWZADZu5lUJwxU/9BWucYCk5totEd+KGVd36dt7lixzGQralEG8OGrfTDYe
         fuXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kxSOKcft;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XoWTe4b9O3y5R3RUij+hDcUvS+37vDuD2S492XD5S4s=;
        b=c+XIpzvBzsmwfbKvvUWpsD5LLiLOmK/uyQmSEhsVHdUZAi6+oLbK8SMPmN/UprE9MC
         TTFco3d1038cLDFGIqQnFB+X5cIgV1uc6R3xNekCLX0drJjEHR5nJ6OxBFLsHnWKPOqo
         x8x+xpW0xgLXFk2YD7ZgjPclwDZIRpRcEfoX3/DvaIxlVUXR0wDeSQ+n9D0aJGo4rL4D
         u0mUdZvvUMkiZCY4DLffzsIDqL3Zw5ULtL7sDGsGfaNZlLOZ9CbyD6zqO8nasdWI4mAv
         dNdLIxa4qYN6EDnix0Kw+tpS2VugmLte29AFWwPK4j6aUGkDfBlzVbL9+C0AwuiX/cpU
         5kcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XoWTe4b9O3y5R3RUij+hDcUvS+37vDuD2S492XD5S4s=;
        b=fuL/gNzYILXJgM0/jJsc+inlE8yw29YKIVF1Go8k3VOIJrbSn0fshStaAjYoTjjEUv
         0r0Dgqzop0rIWj+DUPBHn9ReU8qD7otR/mtlaHqa/tkdHfO1mtxOQnnul8fS3Y7GZz7O
         OmPErC8Gla9Nb7eIVt6KPW8AEeN5Y+THLNi3UbqUvd+sdK/wg20k76NCl4Hle+zizwMC
         1GCM7lePA9ysdiu1OomIDpsJ5NqdPqM+Ed4Mfo2tcAGXE6/6G9zIiHSyGuIE+CKTakBy
         HW6vK39q/oI6gVMmqv7Mvkgb7kiGiWylQljupVeWRVEhwkT6uvPnIybE+fRjv2igaCOc
         StQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532STEaPACvBYYFl9P/xqabV+5pkixa5V1RwtdbVzA+l76Pggtt1
	LYOs323NdWIaSiSeuRTUqnY=
X-Google-Smtp-Source: ABdhPJyea/4zI7pncaKVJY0Y+tZPP97VOuJ3ic51/3/QZ8oGX4pKPpVhWYWz9+aXosi8ZYIcv2fTdg==
X-Received: by 2002:a17:902:8c98:b029:e1:5a00:537c with SMTP id t24-20020a1709028c98b02900e15a00537cmr2672329plo.79.1612353616868;
        Wed, 03 Feb 2021 04:00:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:87c1:: with SMTP id i184ls425217pge.4.gmail; Wed, 03 Feb
 2021 04:00:15 -0800 (PST)
X-Received: by 2002:a63:3712:: with SMTP id e18mr3206683pga.394.1612353615805;
        Wed, 03 Feb 2021 04:00:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353615; cv=none;
        d=google.com; s=arc-20160816;
        b=GT+c519/UrBp17sh3plhYWm5zp12PoMI6ysVJNSikRlt+nmLyX0C2Cx/beeF8vJnmq
         AA8uoy/6XtkZ8t7rET0oFipSFUgPBpQD6u3kVVQJR+2xHXS2kD27tXRYu3zaKn6OMeC9
         puRGRhCcgnOnLMuNtYzSwNb14USIDmiRi5EdgCtNUUdiSsMg/zKytzu7brbh4i1N5IBi
         JHW1qdVWkSliNq+0+OYxgVUOO8kh8ntYJjmQq0Yo/DWgdevDSYfUzjRTneOUl/qhfqHv
         NOniwvhsipOZCf6KEP+jUoKWf+JuAob1cJ/12Tp0j7lromv4ufuaaB8s/FmY0X2oslRS
         L6Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yq2AQYTBwcMSkk50BfF3YUyk3WvoM0RKP8OIdZyLogM=;
        b=lP2g/7JLMT2PSICJkmp71DwaJvpVKMox0EAMMqiz7EMLF3XyE7dK2jb1uhJFNZnLIV
         /TqfHrR8f0D2+ps8v9dK2I4EqqFspCVBqqSr2g0i1lmCvjXxHz5K6iMjxtdJIigLKrHp
         n1k9ymzfrz24s/JU4pX1/L1gKHa7Gf130IfdloRC00KVAZY8JAlt3p+nuDPVQMCgY/Xt
         Ftop1dy5E8l8bu9CncyPRUzqMiGUQLRNJqV9ErmcdO+mzn8vp+jZLwhaCHk4444m34h0
         LPKWgPr2DT+H4QB13UhkgHtAnuenIyMfCdtETH6xZNb8nhe2a8esXxZ5cvrDGi0V1lST
         y2XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kxSOKcft;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id b189si59747pfg.5.2021.02.03.04.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:00:15 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id o7so17232803pgl.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:00:15 -0800 (PST)
X-Received: by 2002:a63:5f93:: with SMTP id t141mr3293691pgb.299.1612353615412;
        Wed, 03 Feb 2021 04:00:15 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id l14sm1991737pjq.27.2021.02.03.04.00.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:00:14 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 5/6] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Wed,  3 Feb 2021 22:59:45 +1100
Message-Id: <20210203115946.663273-6-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210203115946.663273-1-dja@axtens.net>
References: <20210203115946.663273-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=kxSOKcft;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as
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

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index bb1a5408b86b..42fb628a44fd 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,6 +2,6 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
 obj-$(CONFIG_PPC_8xx)		+= 8xx.o
 obj-$(CONFIG_PPC_BOOK3S_32)	+= book3s_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-6-dja%40axtens.net.
