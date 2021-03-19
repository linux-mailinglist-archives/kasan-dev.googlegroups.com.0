Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFPQ2KBAMGQE65RCV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 69080341FCD
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:26 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id i9sf16935292pjz.4
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164885; cv=pass;
        d=google.com; s=arc-20160816;
        b=orXUJUiK6p4dBifJr5HT04Ah2ADz2cM3DmyqvIxhr+fdG2ooxbLCpk1clc2jFLh3pv
         QhmsK+LTsHB+hFkDAw4IPLgCmPknyUpJkPqLv3yBBbMAhCOXBKrBdxDIO36sK7EFxNzj
         75FIbICY7BgFUn+mrp4HuPyrxJC3g7EF0aqTFkXD76jKiNFoIwp5Ta9Yxlvf5m6PHqd9
         7Lkv4udchf/b7epwot65CTHlmLWsB9sKTlEZ9vB5IO8VYEh/5VwuHnhOu82cVp+zFv0/
         xtXJc0qBb3VL/nPcAz1GkLg/70Urz0Dls/6sP1XPeqV9yHMDTnhOKhi1kRAw9JTz1ps1
         Blew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lkxl77viLIzbHvXPY37smvX85wWqRf9lno7IsjVD57k=;
        b=dtSyyEtZxWC++2Sh3fJiZ+UFRoN4l+6jkc2ynkRUL2Tn/boUl0z52truM28r1NVfvD
         BxXL3LiexPRLjpze+4o49gZHEbtTptg+Q6Ou9faySlm67oVJ66TKlIJc8MWW6NaPFfDQ
         Gq7cfAxLzkAoE6XGVp6Uig0xZgbuTHwvZe8WvnWIv2gPJQNsUXJIU/i94T3BI4KWYTye
         JKvb2YFzyQhoeBEhZEMFw37Yqohd5fCbMo0aQz89hvfUXmcj+J53w11A/j6qP0IFiay1
         b432FutH6yXgU8vCb13c8/fcniMR1Drdi+LayQQxtoCVqRW0chfPw/XU3xV8jhmunVXB
         20Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Pp9i5eXC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lkxl77viLIzbHvXPY37smvX85wWqRf9lno7IsjVD57k=;
        b=FR+e0ktkGcBvZGkuwIuJIJceyPZKRZssvHfCuX74obydkdkeadLSpFx64SZ5y0xOm8
         5mf63SheJjVgaNpfddMRjlR/BzNTiYaNJcvSOhM787A6Yg+flPqd6pFJoIMj2X+lWMZT
         EO6MsfFb+8GBBveqNOfYUWtiZCIwyAJYhnsXiwsqyDaaMMN3LDZb+gfpURP+pUPY8vXe
         6yMgeOQa82o/48vH5Lq6HcYlmJR+to2SP8E0xCLv6nldXyyPlnG5ToWkNVJYNYJiWeTv
         XPJH+iJpaMHjFgcOVHgLxhwRJSZTWNY+mEqSuxO6giMdyHI22lkcbN1ubG/hX3ZADshy
         CtQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lkxl77viLIzbHvXPY37smvX85wWqRf9lno7IsjVD57k=;
        b=p7Il7A87j6MC4yrlyjkxMidl3iSvE7dVyQjyP4SY8VLd5CP5Yaazj4m25tsiVXHd9G
         w7BUOpknAQArDFdBNK7qT3DevlAfBCT7mWvX6eG5+8arrTCcW39poTT1k+ffPBoUkdzS
         ps3Gb0mvE2zUhWaBF69t9dfBTEQHBperG/KP0MQkwmMJs4e47FF5hSzJYC5UH39nSRQF
         kjgsFZan79uBPdVIW2B80xl9An5Xt4BR8Ce/PDkaExL0VQyqrhnaepKheFyddH94u2G+
         of9zmIG80pX+wbSmz0kAlTT9D/T4hbjGkYKq5Bmu7wz/HOOfm8q8RBPH+QGvpTV4N3Za
         zpxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zgg8kGI/jtalcMsTp6nbbUc5Gh+PLJ4TDe5APp1YTNlK8e1tO
	p0GhliU7hc1JWEdGbziDmzA=
X-Google-Smtp-Source: ABdhPJzWN/00OU3eGVTt9OBvM5kxe1zt8/Ofqskff+PmCkPuPd6uU6aeK/RnB+2++PA9SVVvZJ3htQ==
X-Received: by 2002:a17:90a:e556:: with SMTP id ei22mr9924114pjb.214.1616164885167;
        Fri, 19 Mar 2021 07:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2286:: with SMTP id b6ls3027167plh.11.gmail; Fri, 19
 Mar 2021 07:41:24 -0700 (PDT)
X-Received: by 2002:a17:902:bd87:b029:e6:4c27:e037 with SMTP id q7-20020a170902bd87b02900e64c27e037mr14645102pls.29.1616164884598;
        Fri, 19 Mar 2021 07:41:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164884; cv=none;
        d=google.com; s=arc-20160816;
        b=oILoRHhBAzuy1TcFQZh2ymhe5ucVhrNGc5FRA7Q/66Ht5PUYkmOLTDdk+piQJnVynx
         bSRn+dFIvft16PoqyKQ8TYiFo7rZE6bxiu5XbDUFFW4zSLLJBlN+hy3Mgj4hJm1KFXgC
         25jgxcpKuncCCozq5QJu/4udjfSQn0A6u4bMNw6X3ANaLkp4W3uixar2HzuhDGbqNjd1
         dN4PiMHJkgJHtXgOAnhXXN6/13EzhRzz3qdf3A219cic4R5c1yZvrHtKGmbtlzFy9cEZ
         TL9H7WakzkEAjRFfJdx/6MJnkv+RLdNqmz6Bld6KHp4F9QJgusNptEF9eTXsHdA2eBlF
         /NBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yq2AQYTBwcMSkk50BfF3YUyk3WvoM0RKP8OIdZyLogM=;
        b=lNQkR5A35yGpc004YULh6JdJEa89XizklX9qGjrjWemqx1RoWMUkM+tiW5ctBebB5P
         mw6d3kJ8gd+Hf7mc2mubMBgizDEuSJet75ZMIIvLDeoYtsM5KgOMe1ffwYKoZEJ2Sub8
         aOKVj7XDGS0USvhTA/RrOGrMCnm3hbeQfevMaxLMXzJ2MCnjduj/e5gkp/GbKtj0QPwL
         c/znvcV+DXQrxJtOFFicLsP0vTSwbFJuSZe+x8cms3cIZvOKlLLS+M4Kb7iCw288CYpi
         s5Me2O4TB2IV/KfPFkHMquBe45WtGdKANjjIXMf+cyy9oO1CnfaKS07zvSMy1wmpZe3t
         sAzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Pp9i5eXC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id t5si360781pgv.4.2021.03.19.07.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id m7so3815083pgj.8
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:24 -0700 (PDT)
X-Received: by 2002:aa7:92c7:0:b029:1ee:75b2:2dab with SMTP id k7-20020aa792c70000b02901ee75b22dabmr9622789pfa.61.1616164884381;
        Fri, 19 Mar 2021 07:41:24 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id y29sm6058594pfp.206.2021.03.19.07.41.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:24 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v11 5/6] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Sat, 20 Mar 2021 01:40:57 +1100
Message-Id: <20210319144058.772525-6-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Pp9i5eXC;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-6-dja%40axtens.net.
