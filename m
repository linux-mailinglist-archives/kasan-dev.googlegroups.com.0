Return-Path: <kasan-dev+bncBCT4XGV33UIBBA7E7WZQMGQEDVEXCUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 151AB91CAAB
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:33 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37625537d64sf16445765ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628292; cv=pass;
        d=google.com; s=arc-20160816;
        b=J9PiZmcssLssgmQdiC5pBGuDCCR+EuWrYXK0GUjqvOWhmO4/nyz2t29puvYNq5hzv+
         DRxpFZVEh84c6tyQqbKkr2aOoRgse1Ebc+vp9k03bjzaYWPz63v5g56hVknBQNZosrKJ
         shgt/cPh9IGrw+lEjfw57UBQ6cA5eQBQ1byacatG3dvFi/sYcrALkHxM6Zgi7SyiIAs4
         lwyO1zpYTOm7KDARHFXxv9+qDvHv3MRDzvUY+rLZPwVSlbEW5vu9QdDTjO/of4qDiz1J
         LDPWTlSJ0z60n8dfopZkJn4Qj3HeZ1PO7SKWtFp1fZtwIh9ULace67s7t+O8nhjvXcZQ
         k0cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=Y4NfP7YCub5wDsBQ+eSZ+Hmdd37RrpPzRHXnotxnmg8=;
        fh=TZl57p08Sj0KYirLCrz8jc3TzJAlYo4h26OHHejihnU=;
        b=o8C1zMueCTmnmpyZJwOtw+1fKYpvOsanx4Xzr0tTUgdsFOdyDQroCqPc+OobXj4/mw
         ZxY/S2nJ4dkx0umHR2+Xuqvta2m93nJfSzSCnv0BNWELVgTL1AOKYKKhOWuG9Hfrf5Co
         c4vAwayUGjqfF7zfyHHK8sPe4at6X/8u6+Nf1WQ+zwtHbqtOpeZID/j7OevEy9EhlpxV
         kjm4a4zOyAcTyCW6u+UnpqmbF2wfiUKiWihLkMoXNuhIy3OoiUgq5OEriE30OIRK4o/d
         xnXiHIFgMQ4RMbO3rLEbPIYg3P36LvPbvD3HxCBDiNRAmBHN8onFv6MZRaL7xq/ZcyHb
         KIbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=DzchPq4c;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628292; x=1720233092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y4NfP7YCub5wDsBQ+eSZ+Hmdd37RrpPzRHXnotxnmg8=;
        b=qmWnIzKNX/BOA9itItTR7qKBnkSg8Qmrikmw0P1JmdfI/wLvuKpis8nsrZa2c38ZIk
         kwdB2iS7fz6HkEnheS2/6o6/jTX0SDFZp0R9QkZlsS5XaXeqOEq8TV9fGEj0kObgvgc8
         LK0hhu+w69yXedwFkgQFnnyThSzPNUSXuLPB1BbAblezkqu6wDUffOoKCOL4+LD004cM
         lLUQfVvW5bekTi4wvUEZK3o2Uw05+QNylEIyra6bJN1AtC+/h2SuDvKMA2UGHXChvRCd
         7oyF7AaRBu7tg2HFJ4d8/7ilCqvYZtcJxb6uJGhzoS4lJSyweD3dT4hfRCU88B8HlOKj
         MDCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628292; x=1720233092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y4NfP7YCub5wDsBQ+eSZ+Hmdd37RrpPzRHXnotxnmg8=;
        b=OBbEqvo9BZL8NELW/zAhYBGBMLTMCUbZ1J7zI34dr992uMtY+auRvZ7KxQ5prhXN7x
         pxRsEiZzm7h9idDfLP/Q6PFAHEpI9N700SsWEWUfU1xhYWCqWhZjC560sXjYc2yAbryd
         bujJwcgIJ/5hDSqK3eEa5tf5dofhzfTsE+wLVhke4ddzydj/AhqulOuByVc7ebngTNgq
         +rer0SHg8Yo7h0/UDPxQQQH6pR91+5Z+ooKN8CyyjPeM74mrpLm24E7SwlVe/AufVhEY
         2yVKILN6uZn0uF/si3IamTnFV5l7DbW/h7lFR/MUkmrB6WFNZoYwD7R3irqOZ2iNJ0GE
         pi8g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBp2fK8vwo+lItxS4KM57Zs/kRnnhTOGZECsfr2bfWDB3J8asJDr+PRyIAc39n0QhMCtH0Dirvl2bQSpLvi1dyWcX3bCAqeA==
X-Gm-Message-State: AOJu0Yzv80wuV0RUwVQ9aUteVMHNhrDFRUMF7zoRlH0bI9V1GEYp2UrW
	IfVZroxpDnOkO+Co9grbkYGytXDHiUcwfqAm6A2bUGEUk18ZE3gp
X-Google-Smtp-Source: AGHT+IG5klIg5O7GQWB7rgkpGpPwu6id9QcXkiX74S6lTe76SLwZb0Kv83YA3Xuw5EaxDDNwOvLiJA==
X-Received: by 2002:a05:6e02:1cad:b0:376:410b:ae69 with SMTP id e9e14a558f8ab-376410baf10mr234988815ab.15.1719628291929;
        Fri, 28 Jun 2024 19:31:31 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12e1:b0:375:c4e6:a46e with SMTP id
 e9e14a558f8ab-37b140f8adfls11399095ab.1.-pod-prod-07-us; Fri, 28 Jun 2024
 19:31:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCad3bFLUXTXlHZuxkc+T4TtpjreVhxnVh01ZzkD+cjA0bHNVOGPvycWEs3kyW3UzxstXKryqU+PgyLNtXFb1/QG5/B1PQbgJ3NA==
X-Received: by 2002:a05:6602:21c5:b0:7f6:19df:650f with SMTP id ca18e2360f4ac-7f62ee08ce5mr7080039f.7.1719628290508;
        Fri, 28 Jun 2024 19:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628290; cv=none;
        d=google.com; s=arc-20160816;
        b=D4YzqANQcyCOE6q9x95IlXHiAEXLJS+IqYUpy5h1RVJ7kFqWEBxw8yc68o9CC4oOL3
         LAQR6OKGCUAvu7n7dK7Yy47XfsFYgvkTZ5+g9ZNXppKv57fnosdpuzQUj1zJvpzA66w0
         Sr/BzUX3zrkQmv3VhWeb2TmgXVOh4azWRla7l5r8IM5V7+C5NRVi12TCMahguPiycSVz
         2GcDN7q8zHe96Es27EEJ1DaCmcwtjulgW0c8i+BjhBXHILwo2Zq0whrRAbasCyLrFSM2
         zk05ZgTLw8HRijSnvMEvlsSvlnuaQ3lh/GPdPI2BIRQVCV9RK/aTCeZgSffPas+cWbIa
         ZDOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=arIzzeMhI3nZbEWfFGT+NQFiyvyzfX+UAhvoXMy4qI8=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=LN+WIo0VL30ZffrQ1lxEZEbpZLoZaVN6wYOea/P/xpnw2ncle0WfyOnohYvtMCStmQ
         3mqkfWBkpinBrjIBWmbEVHvj4bVdfHrfw42NZxb6PE8B4d0sQozG8quQ+96DOWAJTWLR
         xx0YuWZLS/oCNfY3DbWxNDxNKB3nchf64bsPITys17X05dJuctGgS0OheQIg8FDCTJIt
         3+tZoRXqJ3Ff4yfFETooBoyT3K//MDryqRl4NIBo6PuYpdVR4rRRKMgtrDHM2OkeEMoi
         YABYo/NELSHwVcTzqW9tKCHoe/+tTKutAwnSkijffolU8ZY9Z0gqa1uZMDHGnYX3UfEB
         96Ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=DzchPq4c;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4bb73dc2f60si116880173.2.2024.06.28.19.31.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 6997DCE3C29;
	Sat, 29 Jun 2024 02:31:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9767DC116B1;
	Sat, 29 Jun 2024 02:31:26 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:26 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-enable-on-s390.patch removed from -mm tree
Message-Id: <20240629023126.9767DC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=DzchPq4c;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kmsan: enable on s390
has been removed from the -mm tree.  Its filename was
     kmsan-enable-on-s390.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: enable on s390
Date: Fri, 21 Jun 2024 13:35:22 +0200

Now that everything else is in place, enable KMSAN in Kconfig.

Link: https://lkml.kernel.org/r/20240621113706.315500-39-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/s390/Kconfig |    1 +
 1 file changed, 1 insertion(+)

--- a/arch/s390/Kconfig~kmsan-enable-on-s390
+++ a/arch/s390/Kconfig
@@ -158,6 +158,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023126.9767DC116B1%40smtp.kernel.org.
