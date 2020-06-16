Return-Path: <kasan-dev+bncBCPILY4NUAFBBR6RUP3QKGQEZDNGXKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 899F41FB723
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:44:09 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id m10sf9860617oog.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:44:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592322248; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ujz6JZe+cpR0Hor66HWjVI6sFBQURVDETzfJM76qIDCTis1gsw/1rvpcEpLykKq6Wp
         PtYDTyD8NkPyXuHhUjHVCLs07vWO1LRo5/MwMttLtmTjCORi6eYLuhHwfWOi8s9Zplks
         HVBQEAQ6W5Rrg4SmO5xd1sJtQU0l2dCt/TP4GJxl1ORxExcauvbSwo1bqCigpxdupzH4
         aZmV9zCZA78fuJ0R1T47jJyCXT/Lgu7Aicp8vgQnM/QwtkY9/9esATvTXeWAfrY0+TdN
         q06NFmy4/MX6I44AUzJqH/I3UkjTOJDKsGFiZXPihpKgztQ5aqeARaHXb1XcaGNgeygb
         LFDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Cuji7OqIXYSwA40bPrAq4XGPVsYM5ILatcVwyVHe5zk=;
        b=r+eoGC2jtB4Ppzs9qhvX0ClZN7Kro6TSJXIGkR0dJK6AkUJ6yhJD6lPG+k0Vw3udBc
         YdVqRiDMvK2vfkMdaOl9LLtbZNDaXq63t3sKCOlQjPlkEse0AyEZnUFzj0x2/KWRN7NA
         Ih5jVX7AfYlr4ulpu19wze2Nrijut6ohGr3/0wdwrxdUlZwjZ4LKL4EWOnph3OwYAwWg
         cZLcZ+ao+OdhCASqrGDS7nEf4hQXDjAFCrWbh/+VuOpbywDE2fA+LpQFzPolVRVKW7aX
         g6FbNZ5yjbyVRMExNM39QQevohxO5RmhzHjBUT7lAbM9ElWN3tk7yr7b3XZVxnSt1Jof
         jWdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cN007Kyf;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cuji7OqIXYSwA40bPrAq4XGPVsYM5ILatcVwyVHe5zk=;
        b=mhkg7Tc3BQt8GnnLMaUtLtrC2qalUL5qeF4XuM4yc7RtKUtEZSHJBR4FPcfL+OpzQP
         lFV4WZ6g9inUABjEPQFPQpKU3z+cwQjZ9UZ578tg8EEgPppq/ubhidQvjRDeRVBt8Dgl
         IwHWbwE0bZ5mcGxqjLxgvA0FQlnvVMcwaMnuA4EuVN3W+dWfwAG6ozj2RU1cufV1/Br1
         pC52QUBYWUN0DMNJWZUCMtttZ7FnTf9QlMfyMoM32uusNGZdYjMK5o20g/KoTMTh9gMQ
         A4TuQgzN8UJk+HP2o3GjjJLGfgEKWi1JFDV7kboOP0ozMGjSDLeE1n0tYTzDNVlJlYMj
         1ywg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cuji7OqIXYSwA40bPrAq4XGPVsYM5ILatcVwyVHe5zk=;
        b=B7AeiwcsymRmpcfEuiUV0M4r5UIWSIqoDDpm3ry1L4m8CQ4TEOMyLnXhrLmyZH0syy
         oVK14J4Ixq7O66qsHzH8/NpErU7fM7ObyhMlzejtUZsxM2Ikf67Bi68BL+LEIdQli5yB
         SOVygRzmPGp/SgKhGBGnWX+1KKsq1Vndwffs3TAE9Zjwc6DBNG9Mcru+OPPQl9A1wcRb
         ldyu7GOXMHRCUQrpYjopvQLG6MIjU7Cj1q7FHmbSbZ0bXktwMba9xwiq372Q1MrP40OG
         qXpmR1s5zsQqKSGKzhf62RHX15pFL7j0SALSziL4E0FeDCIlEfkx4mtDJy4epdS3yikw
         AnEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kRg+GKd8OwRD9mvMRWAZRInMLbZ34LTI/1lulOf3M4s1e7u5m
	cpJ1i03A9uBn2iwt4Sq/AIk=
X-Google-Smtp-Source: ABdhPJzsx4C9EHn7wmzO52XI5F8fdtCYgDGJ0FOlOwBuUNZrkJzii3dk8abdOLOasBDtoUOSM/hQhg==
X-Received: by 2002:a9d:6d81:: with SMTP id x1mr2995726otp.355.1592322248037;
        Tue, 16 Jun 2020 08:44:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c46:: with SMTP id f64ls3943460otb.2.gmail; Tue, 16 Jun
 2020 08:44:07 -0700 (PDT)
X-Received: by 2002:a9d:7845:: with SMTP id c5mr3003213otm.304.1592322247710;
        Tue, 16 Jun 2020 08:44:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592322247; cv=none;
        d=google.com; s=arc-20160816;
        b=1InFqk8FKbMOEy/bYj9ATgHGGzFq9x3mhAeSZnuerzxXy2Ig+OYtiYXrngZqEel1cM
         3zsyYpfCPFjLYBrzfeTFupkwgo4IP3RCwH91DZ0R4lCORwCr0V3bNTMg5xP8rNTfhvcH
         RBihbykMz+bPsRYvAat2kWXXgTsEzq+uXStmeu38H+DLyfySBy5F81btynC/63rBuwER
         /5G6dp6ZhVIA+h+5eWtKpnSILXCNkEm8alU/cHpV+dZor0izZb1iByl9XOSWYw++Rs79
         doWt/loty1Rn9+Lt3nEUnw0dmkLlQFF0uN3ZSDN9gnmdT0I4cte73jSSZm7rBNrlbKaz
         J6Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=L1dWaJdahdYkTYggpJaOYjCAjNoYYXeI8nNv5UV4mug=;
        b=ExwD6oWQ8aWK/Op0iV6yqOn5mMaKPFGoo4e+1on4yHSIpOmN1tnj01OvqYgxseem4x
         fJSFD1NZ/jdfhrkPZTaaeoCH+zWzl5J9dKLJWNLK5Rp9Bje3PVbDmcns8vw12+Sqlkwf
         2q4wP/RQhhvp4WEjM9WfVT2aEbqRbKtTZUllmxKO5KIH7w36dkxQ+pMqNwPs2LJEioGx
         Qgo2sbUhgH2rc3oKSQaqpuNooIJUj42Wxij2v7mwwGO+9jczWH32N0+t3bOSaPHBtmjD
         nIyl0q38o63U5jDPHvsm9fXCzKDPIMGwTd9/nEi/OQ2P+leBh+ioXm4GhlFHDDW978yw
         x2kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cN007Kyf;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id e69si1549900oob.2.2020.06.16.08.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 08:44:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-295-Oroe0pwpNdy3o79o83xcow-1; Tue, 16 Jun 2020 11:43:58 -0400
X-MC-Unique: Oroe0pwpNdy3o79o83xcow-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id A289218FE864;
	Tue, 16 Jun 2020 15:43:50 +0000 (UTC)
Received: from llong.com (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id BA96B60E1C;
	Tue, 16 Jun 2020 15:43:45 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>,
	Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>,
	linux-mm@kvack.org,
	keyrings@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org,
	linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org,
	ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Waiman Long <longman@redhat.com>,
	stable@vger.kernel.org
Subject: [PATCH v5 1/2] mm/slab: Use memzero_explicit() in kzfree()
Date: Tue, 16 Jun 2020 11:43:10 -0400
Message-Id: <20200616154311.12314-2-longman@redhat.com>
In-Reply-To: <20200616154311.12314-1-longman@redhat.com>
References: <20200616154311.12314-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cN007Kyf;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

The kzfree() function is normally used to clear some sensitive
information, like encryption keys, in the buffer before freeing it back
to the pool. Memset() is currently used for buffer clearing. However
unlikely, there is still a non-zero probability that the compiler may
choose to optimize away the memory clearing especially if LTO is being
used in the future. To make sure that this optimization will never
happen, memzero_explicit(), which is introduced in v3.18, is now used
in kzfree() to future-proof it.

Fixes: 3ef0e5ba4673 ("slab: introduce kzfree()")
Cc: stable@vger.kernel.org
Acked-by: Michal Hocko <mhocko@suse.com>
Signed-off-by: Waiman Long <longman@redhat.com>
---
 mm/slab_common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 9e72ba224175..37d48a56431d 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1726,7 +1726,7 @@ void kzfree(const void *p)
 	if (unlikely(ZERO_OR_NULL_PTR(mem)))
 		return;
 	ks = ksize(mem);
-	memset(mem, 0, ks);
+	memzero_explicit(mem, ks);
 	kfree(mem);
 }
 EXPORT_SYMBOL(kzfree);
-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616154311.12314-2-longman%40redhat.com.
