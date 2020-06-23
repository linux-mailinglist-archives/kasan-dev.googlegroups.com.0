Return-Path: <kasan-dev+bncBAABBOFAYX3QKGQE7TCNIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id A68442045F9
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:37 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id x22sf14156101qkj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873016; cv=pass;
        d=google.com; s=arc-20160816;
        b=iP4+X2OPUiNwTkBLywQhcy8q2uWAmlfZAjomfGGsEuTWnrlXbXxu4gaPkEitU8l6dT
         ZaioKNFnVHez1M0jCOdGmH31CG9fbbs55b1CHREIbWL8ul3/5MgzvJlTfpSsX+b21TRE
         fCSSLhHJYZPjsjj2erm+6A2I/7ZNA6X1x3asEI7R4H/UvGxGz0T2c0GdKy4VA15GfyGF
         WEGPCIn1FvRn6nvGzVd6wHG936If1X7WpmP80qQcSfIhXUKplBKuSzZfFeXjDUJf8jtD
         4hPEFT/5K6c5vKLb9Ao+lyee7POvKQOQSWVGwipbbgVuay14+SxYPt5oF37XRoVyzi25
         eNvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=7kOiqxteaud5LCMweE1M9qibutY7PdsGme6UaSA93j4=;
        b=dUiBUu312IBi+rRaE6nV4M+Ing2ADX6TajLwwjQG4zFFLxVEVd/egfGV+5XGkcNO8C
         4esttO2/fp0TdKHP6N2LfpdB6XXTXz/dDYj+TQe03xlI9SktWOSxiUHD2HGBbKHYmweY
         V4IpXBfCi7M8aoUmRKkmQDKdSs0UHxMxfYIn66crGpZHCyrIS7QSuiUhpHKTjlI2BKBP
         p+fvVFdJdeQ/L82GNMG2Y4i2P6iPvGh79WS0H3ESmuWp55ci+DQbIeQh0C9G+Ke/BtpV
         F15sq0pbKAalKWkfOBUlQs3oESzT1qz2zKDPpNnKxaEhK5Z7Jr8e7JuhD49/1wORvxEs
         lVvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rnEmpZkI;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kOiqxteaud5LCMweE1M9qibutY7PdsGme6UaSA93j4=;
        b=OOG0gIjuNdhTH8WtjC95fZ7J8NmoAq4sAhjB6irFrB37BEN/2SxLhRjithaLGtEyUb
         wjaov2DY7vfZ0dnXRRwC8dvVtvKRztCmHnpfYADzHiT9Y+YIVOYWec8wEu33O5bVcOIt
         USh7vz2EWBBpzIP9zV1/lV0j/7XrLUO9u+YgvBYQ4V3VDafaZGoPX7L3+UbVff9iTXUO
         NHx7cjuZ5A01CReJbLP78mIZ3ATaZGMeHJZt1dlUVis2UtNF/oKIiTM6kM39/6nSvAYK
         B6qLG8cMFy9+m/PdCNula07GeT4VMd3yloFW9QmJ4CURIojEcm5RG52DB/rp8hUEgy7C
         INQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kOiqxteaud5LCMweE1M9qibutY7PdsGme6UaSA93j4=;
        b=UILHAdKgg/oUVDTmvHBxKPF2DRePdImDvzXCIFfDZBQgQq/UDS/maXW7pZ3aFhHJRK
         phdjelQ9w2+eb59RUo7rfcP0HdBu80XZhrE0LkGozKx1kItu+PJpvY3Z2Ug0bGdfNc8F
         h8PU5Q9/71c5X3L2bQTeEN4J0IZMhkly8k77giORsIccFwGlI8EC9qySZJlvM70zHiUD
         L2Qg9mMRks3vyeSP74XX9PuCRhP8N7Eu2ZoHMtVhs40mAOL4JtzLP/LJjc2mUFFHfGng
         UP8L+TG0lUMtBzCcUeFzeBko0QaYQadpJrFNcsyRdoFHLiP08NzixsSCM4nU5mf17+9q
         CTyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53264JiKdIQqXEYr5c8uB4R7If+r5H5ANH5oWWFhwOY0HmmNMB4F
	2Cux3PrU4eyMNSTq/OMyV4o=
X-Google-Smtp-Source: ABdhPJyhu30idxfS2qDQuBCvS1Leqp6YtYcdRvuPxnnps4eDh1MRdXF73VCIsP8+kibvB7dRCt/AEA==
X-Received: by 2002:a37:8505:: with SMTP id h5mr10776144qkd.331.1592873016734;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3eec:: with SMTP id o41ls2412756qtf.8.gmail; Mon, 22 Jun
 2020 17:43:36 -0700 (PDT)
X-Received: by 2002:ac8:895:: with SMTP id v21mr19167170qth.185.1592873016459;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873016; cv=none;
        d=google.com; s=arc-20160816;
        b=HriRQiAtgvBKjNLSDomxEw40KWyTGBW1H7LSBysiYsP5XVx+kJ4WK+mmMJy6RHIQni
         qFV8ySq1ufVC8eyeYNkC8e3bYd39FL57jZi+sEH+WiOQTTiuaY25dxeXNTkgILBrENpx
         rhClwXQ/uSwWlIF/WnwJ//rq5zAD4Kmdhv8UgMN10Um7jhkkbIMbBRE073YFJBWBOq8X
         LC7E3jWI1a94EgFwtcOMd26XE692qkvfviMHLeqyUQmaA42tdyQ8ADdr336kMhiGqBgl
         ORnmKu2GXvtQ+NUkAY5pjijTRfOdiqTSZnnWYQWQFrrKg6W3AjMLOwn5irorM5x9kwVM
         pLwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=sxEstT+T9HK1IkvKqJeQUqFcfJPzxvJkHsEgYxTz7nA=;
        b=Pw7p2S0GMF/16EJW+oNXRKIuSs7JxLqQA57YSyMrB3jZAIHXOT8NCZDIIWesn5J7Pl
         brxNBUDBcOUYdG7nX2ibPpXJowpxqM5KVxUXquSr+652lacF54m/9P4dBV9hUZlnq2Q7
         51mT7poWMJwp8qaVxNL5fXN5R9U2qyfm1Teb0S+ixA8fMu0S/UCekMOOBkZ79F8GSgQL
         UFuQEaVDhHUrEUEvQetds2ej2YBKs3obgV7mYHsZzej0X8dH22t8Zvy774YTCfCnFgie
         AMWqeD9uqvXSnMOv+/u+LP4MsXbTYF51XHc7ZYCHODXX5GgjTUsljbeyDGSfS+YHmV8G
         IpGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rnEmpZkI;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c67si886234qkb.7.2020.06.22.17.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8BD5C20780;
	Tue, 23 Jun 2020 00:43:35 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 02/10] x86/mm/pat: Mark an intentional data race
Date: Mon, 22 Jun 2020 17:43:25 -0700
Message-Id: <20200623004333.27227-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=rnEmpZkI;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Qian Cai <cai@lca.pw>

cpa_4k_install could be accessed concurrently as noticed by KCSAN,

read to 0xffffffffaa59a000 of 8 bytes by interrupt on cpu 7:
cpa_inc_4k_install arch/x86/mm/pat/set_memory.c:131 [inline]
__change_page_attr+0x10cf/0x1840 arch/x86/mm/pat/set_memory.c:1514
__change_page_attr_set_clr+0xce/0x490 arch/x86/mm/pat/set_memory.c:1636
__set_pages_np+0xc4/0xf0 arch/x86/mm/pat/set_memory.c:2148
__kernel_map_pages+0xb0/0xc8 arch/x86/mm/pat/set_memory.c:2178
kernel_map_pages include/linux/mm.h:2719 [inline] <snip>

write to 0xffffffffaa59a000 of 8 bytes by task 1 on cpu 6:
cpa_inc_4k_install arch/x86/mm/pat/set_memory.c:131 [inline]
__change_page_attr+0x10ea/0x1840 arch/x86/mm/pat/set_memory.c:1514
__change_page_attr_set_clr+0xce/0x490 arch/x86/mm/pat/set_memory.c:1636
__set_pages_p+0xc4/0xf0 arch/x86/mm/pat/set_memory.c:2129
__kernel_map_pages+0x2e/0xc8 arch/x86/mm/pat/set_memory.c:2176
kernel_map_pages include/linux/mm.h:2719 [inline] <snip>

Both accesses are due to the same "cpa_4k_install++" in
cpa_inc_4k_install. A data race here could be potentially undesirable:
depending on compiler optimizations or how x86 executes a non-LOCK'd
increment, it may lose increments, corrupt the counter, etc. Since this
counter only seems to be used for printing some stats, this data race
itself is unlikely to cause harm to the system though. Thus, mark this
intentional data race using the data_race() marco.

Suggested-by: Macro Elver <elver@google.com>
Signed-off-by: Qian Cai <cai@lca.pw>
Acked-by: Borislav Petkov <bp@suse.de>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 arch/x86/mm/pat/set_memory.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/pat/set_memory.c b/arch/x86/mm/pat/set_memory.c
index 77e0430..d1b2a88 100644
--- a/arch/x86/mm/pat/set_memory.c
+++ b/arch/x86/mm/pat/set_memory.c
@@ -135,7 +135,7 @@ static inline void cpa_inc_2m_checked(void)
 
 static inline void cpa_inc_4k_install(void)
 {
-	cpa_4k_install++;
+	data_race(cpa_4k_install++);
 }
 
 static inline void cpa_inc_lp_sameprot(int level)
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-2-paulmck%40kernel.org.
