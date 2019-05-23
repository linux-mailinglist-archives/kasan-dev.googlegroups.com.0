Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZG3TDTQKGQENMZMCXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 044FF27568
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:42 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id q63sf931584vsq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588901; cv=pass;
        d=google.com; s=arc-20160816;
        b=w96L4Usz5jIFzZBH3TF44rgLh6fHtadta8dCFxAwJFLKMxWJEISPMEnZvIeA7rvv7c
         7VDnBbo/6e1SybJFf9BUV3Yf1Zrtblp4bK6MloojgoBxxbzbMijRt/eoV5Kd3D4gr8z3
         0J5YG/dmKsJx9GBwen2eexhEudaQAC4rGpRFnyIh5+Mj0DFc+V2YT8ZYfY8q3oVx0s87
         8U4S/OMmGyARdN7yIh1mDA8Y+9CsSgRZYbeYLx/4AsFOgD/w1NG732d2/ZtJ1kcyujsF
         rODjyWtOt38yUsyM7Rmi/Twr+Tz9WWVC76Zm9ekqEhs2HPiyPNaMHd0i08FTdYkLEr+W
         E10Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LPVaeVIwaXsbibtCMinlCJAdpvwYmZ6l8KqRLy983C4=;
        b=Hkt4tpA8y2WmJIlOlscOClYOT3Uxok7EnWRF+Hp7IcVn8SkauvlN0juOBoqe7jKpX9
         JgsRN0hLJ2Yxaft/8Cr9V2y+GWMvkrVDMwErTw8xC/GoE2SVyRyHR/ORc9QtkRi5ESj+
         gC0vlOvz242/fh8tf5Ra5qGdCPJFXHE9nCymLbpBuCOHG08KbmzJO96YF51lv1zzFWxA
         H+msW9P+yiHdYgy8s1bD9RCUcjgNb9ZQ73UG2kWXXYhpljnqBxAZnzRR6aXzHcQnGP/D
         eyoy85Nkgy+fQgumv6H6dXoRPwwO2F3MhXL3rIoPh3gArkrLo7FVPU+NDTt6dYLnTRio
         wBYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=KPTskSP0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LPVaeVIwaXsbibtCMinlCJAdpvwYmZ6l8KqRLy983C4=;
        b=XPzOxtHjeeUDncxZbs/qpbUiNXhi5j+Lya5buEXoimwW2uMuKeji0tY95r8xN0l7Vy
         oYYzax5EXaD7MKVsgDAEUjK1SSJ7xawhXve7aAu2mAdF0N+9zG9DcP5rM1i2tPOwGzsW
         LV1z6Zns9K/SpI9jVa4t6TllNymWwKI7mcJc7nKOsTnAf/13AVTxr/5jo6597g10LyEf
         53ycQPwvwSEt9JjsyzUekj2pusDcye4kYktboINUwT667Z/ZTFb/ZHygVFCA/TYj9CMu
         Lm4ph9uRZvvUc/CjJ23nmRI0qu1ad5d37HYTB5wsxePx3omMtrU318sMnSGzaGfe54M7
         iDOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LPVaeVIwaXsbibtCMinlCJAdpvwYmZ6l8KqRLy983C4=;
        b=Jjhm+oZMwag5mlzqSaaV20rtYCPsPgQCG0oKXT/ZPaTf1bLTZFoy2NL+e7e6OKvXJn
         j5VhwTMhRThoRofYq2eGE01ErsSgh4BZ3UwbTO7VfeHHvL0oRwzIqLMo5O0CQlP6Uipt
         q9rpDEKd1OK7t0Hm8zwldBkhz82MnUWZInT0ugQPbbhSF6W5oJFwo3N85RUoQjT5lgRy
         TaYxrG9DoqMRe/RUvbNoMSxAq26nCmDpF+eY1lqZVK4q4g4wX/F3zawsJGPUmyDpOQzZ
         m0qEh9l2ut9OvbWz7olWEuOG2czP1SslsJLtbohqEneVh4yhq+Co4h7aNZcyRUxBX5Z+
         2zEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGNLnE6UCCCyWrJ4Y8Slac96heJW/ekfDyr+FtNquicroeQu90
	5gwHx1dQV+Zj+lxAPmMa8r0=
X-Google-Smtp-Source: APXvYqwHbgOiekJhgRURdDaP77H65T2n7Cf+ghR8g6S0Oo9YtwTXKvnfFTTuSR+fN9a/yB4q+IKSHw==
X-Received: by 2002:a67:f2d6:: with SMTP id a22mr3454927vsn.171.1558588900994;
        Wed, 22 May 2019 22:21:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6818:: with SMTP id z24ls283134uar.14.gmail; Wed, 22 May
 2019 22:21:40 -0700 (PDT)
X-Received: by 2002:ab0:2c15:: with SMTP id l21mr6982531uar.139.1558588900728;
        Wed, 22 May 2019 22:21:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588900; cv=none;
        d=google.com; s=arc-20160816;
        b=DOlD5oi/zIHAuMeUuZxxwx6Lt8uKF4AbAFtq1UbqEUsAWscAmL9i98buS3JcXbtaGj
         AvhTgmKlMT+9OuvmGdHKdRHk7Wnq+JOVGFxw/lvXFh7sIITqSl+jHbsmjKu9lW0NqdI2
         vlTP4I9wxVDAqPVYW4GsNhevNR3O4Akf8BtLJVaGBiifJqc0KOcM/apmvjx+SdZ13pAh
         A/cTJSVirLRSPaxjuiTzjUae1z0EOpA3yKuSWPP3PVUEhlwyaA8Y+YuGCh4Tr0jldufI
         z260H54PrdIJ+19iLf8Ed3QoMQ4jq5KuGCKGz+gpS1R/k0eoPlG/WgItAJowVQyMxgvy
         yelQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iF1wg4kH+vQXTxBoxOOgIwNClHkp+K2oqjDeg/wjey4=;
        b=X/dUeQENhyxRH9UaYJyR84EtR+sQuZvg+VeFbu5mq9CzcVMjMY7SghDiVFarXtHUjG
         UpZd5VFISUdObFwY3P9ouJFOSnk6V4d0FdASJeI6421J1A0DbfaJgoLo3Rrh6p3jcnOI
         R1ot8Fj5SNOwl4Uzcqh/iyxHpQwmrhWtfUn/zeQXwvkD0/f+ooUj0g6gfCe8Ap4vGOyZ
         Lux+JcJHZKPFOikaHySu90WjEtOjE7nz41P0ygq9SHJD1f3wQn0plRucrqQW9wtO9L8Q
         z3VWte4/33wY9Y0YUqeLljtxhUbC4fO6qJtTpDhBU0idsj0aVdPAXyu0PnyYEqszXBcZ
         se3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=KPTskSP0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id v191si1852298vke.0.2019.05.22.22.21.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id c5so2175645pll.11
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:40 -0700 (PDT)
X-Received: by 2002:a17:902:aa91:: with SMTP id d17mr91896703plr.251.1558588900471;
        Wed, 22 May 2019 22:21:40 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id v1sm27799306pgb.85.2019.05.22.22.21.39
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:39 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [RFC PATCH 3/7] kasan: allow architectures to provide an outline readiness check
Date: Thu, 23 May 2019 15:21:16 +1000
Message-Id: <20190523052120.18459-4-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=KPTskSP0;       spf=pass
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

In powerpc (as I understand it), we spend a lot of time in boot
running in real mode before MMU paging is initialised. During
this time we call a lot of generic code, including printk(). If
we try to access the shadow region during this time, things fail.

My attempts to move early init before the first printk have not
been successful. (Both previous RFCs for ppc64 - by 2 different
people - have needed this trick too!)

So, allow architectures to define a kasan_arch_is_ready()
hook that bails out of check_memory_region_inline() unless the
arch has done all of the init.

Link: https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
Link: https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
Originally-by: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
[check_return_arch_not_ready() ==> static inline kasan_arch_is_ready()]
Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
---
 include/linux/kasan.h | 4 ++++
 mm/kasan/generic.c    | 3 +++
 2 files changed, 7 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f6261840f94c..a630d53f1a36 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,6 +14,10 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index a5b28e3ceacb..0336f31bbae3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -170,6 +170,9 @@ static __always_inline void check_memory_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return;
+
 	if (unlikely(size == 0))
 		return;
 
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-4-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
