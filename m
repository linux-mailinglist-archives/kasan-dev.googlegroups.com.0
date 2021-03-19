Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCPQ2KBAMGQELT5E2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A7E58341FCA
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:14 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id x201sf13128227oif.5
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164873; cv=pass;
        d=google.com; s=arc-20160816;
        b=HowhP4YvRHXhOpTLO6A0Hzt16uzl8DWBMaQFTc7Qd68dVLZATIReBK8EudfhMY7wcP
         apfJbXTbyleArzhtnV9M2D7Yuc3f4youtPonEPZy66fMHnk7hFViMYghEOS24gCSmi1m
         BUiQtoneKUZKaSPDLUYYNaj9lxzi9ymUsgQi1ZiGf449eCBnAZ4ujlnCBb7dNPUkZYvp
         A7lnnFdmX8glu8o5TXhQhuqCNoEa5DfLFZJSmLuXGyRKz0phfNpefZ0yqCAauC9qM3NF
         UTUaGUqcG7IYsE86cNd6wIcfoUPSk8vbz6NWj+Nbz+/lHml+28SLMlhkdBu1RvVaMfTo
         SakQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3zMgT8Fs1VKhoVMBQyAv8rx5+zJACCVmT98nEVejz0U=;
        b=xPLMJ+ohAh23a8tvdF/f2ZTGvXOSRxSuTwsUMwP4gHTlxSUyn4Gt4S9dtO1K/fOGYV
         kxb3sGlUX39KLNRrq5jbgx3UYs71V1a9LRE2Y+eQ7hiRmJpRmmsOKhJai5GRbcU/FsGs
         ZEvx5coHgf7waMKwNAu4hUJXgkCwhEd47Hnp/2txuLZss145A+hbU/yXyHNYE1FuqU1R
         RVAhFMR2USGzKGuHaj3mzgEZAONaXRduhW2145I9YO2zWoHn8cdtmTuavp/8XQwhLVji
         4rstOlJQS+pu/rLFJIH1JeA4suNRMENsIi5U6tNzKsgJcSrPkBEpLfoeeFX3uovZxqrL
         PBvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FyZSmlP4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zMgT8Fs1VKhoVMBQyAv8rx5+zJACCVmT98nEVejz0U=;
        b=sPzFQSHcZcN0cuxfOrg1iW8q/lHXRKHhuLjREH7uX09pmxzv/hsiILn11noGoLgma6
         vMSphch96cObq1Nz/cnzTvna2RK0KjEpzgO848llS3CVrUPt1MwYAWsYgfCNCC0Rd0YQ
         r+IJFYfQm+qjYOf/5yYwJGyKN1fCWGV3ZCje7NGNd4h/brQaaASNTZCUIeO22xzOmzu6
         jhv+rpIK75OhWOmQEgEHD629KxUB9SjICJsug6TCUQr9yZYOkitymYrkOxc9gfKWkP/v
         l6quV+WfKKemJd81B04TLzXtQTnnzNuWwwNspp6QZSeMDbgk1BNitmSuU0GoNzIm25LC
         b8aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zMgT8Fs1VKhoVMBQyAv8rx5+zJACCVmT98nEVejz0U=;
        b=QABf4ofK96NouVuIRjYAxiV0TRuYPeCcfbCpv1D6EaxMyKMWjfXj+DhiaU97JIsRp+
         OGfU9SyOl3npJwguqUvPxgSQhvAC8WFegWNkMjNP4Di57yKTPXYUdaYWbgp6gc9PHijo
         Ih70c92RBKlM3/fxVT3PTfWOZ6SU0XYUm/Oyu8DSvc7Gtsr3FPEsRg0x195KF8J82S4R
         6hyxuGrgeYzDxxzgdW7r/YIz26nyn5O1jQ6eJpSbSro6lfjvIAdqFwOw1+kHx4ue3ZoL
         Hw7bFDA9Gcr2Gg9Kfs57wye9M89GhgjRedrdOQqm4zUfl5AEw7DKwI774huac7NInBwj
         GA9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Rf85Qmdr6mz00Gma2X0rSoOs6UF6/sEifvnzBs2A04Adah5bX
	1MFhWimJL7Ydn7lxQ3yVN/g=
X-Google-Smtp-Source: ABdhPJxVTs71st5UITPl5qPlKKA6LbEG3y4sZDoL/EIo0ZQQKNyWeUhcYyP7kTwWQ9WPMfQNG8CqdQ==
X-Received: by 2002:a9d:4c8f:: with SMTP id m15mr1414139otf.16.1616164873610;
        Fri, 19 Mar 2021 07:41:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:69da:: with SMTP id v26ls1395704oto.9.gmail; Fri, 19 Mar
 2021 07:41:13 -0700 (PDT)
X-Received: by 2002:a9d:6e8d:: with SMTP id a13mr1389572otr.287.1616164873299;
        Fri, 19 Mar 2021 07:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164873; cv=none;
        d=google.com; s=arc-20160816;
        b=OtUBXJ2WCmwg6U1hri3CLuZkiOMAr6Y2jZHyk601Ir1PekSs0VZYMyA+BV1sJcY/2Y
         JFVW82NmV/ywsfEbj9MSjaCmVB2sNJZFDFcgeygBv39dwrb+mUn/k0NuTAkWGU8bsSu5
         INZUsmqxoEsnp4Aw4sTgnqel/OZY9b8GumNUMMxJhWgvwF3Alx1xC+NP4B58Md4Zb7Kr
         gWao60oQi3b1ajPadI5T6eSqK2Zt/4ZWpD1GzCnpOoDZDWoYTAnvdDYvi2i8R6DBtr99
         Us1vSXFW1Is1wd7Uun4WNUR0ooiutUS0jpEBByPTcU6Xrz/olLr8tLAI5dHrCuOsLKDH
         lksg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NqhHo+YeTtQNKJqI1Nmg9Lhc7h/uxmrUcSCxPqX7mCM=;
        b=ShNw5BGOeq2SQhtFAB2CEPAts0tTlcXFSIXOaTBrMblQB3LFt/gtVB63r2D/170lg6
         gdArP492vVnJ6eCa4mwD7lTQ3YLX7KmxJZKvemDkYYuDJ7KQPn5N/r1t+EoDu5GnxBRu
         nXb5vrUxNXeVvFCk9UjOhlh2I3ppw/icyTemovWYDpc/LaGhHp+G7O0Vihhlo2gCbmDn
         0VacXRvJ21SqF+6xPgz4N6GXNcrn9CA2yovGCaOwsKEhliXf+/1i/44IhR2EQPhruCNc
         wwrnftpvVSFgNawq6MqXxUExmohgpEt0+4/ab8V8DE9uk3blhBtKmVliPcLOvVPck0Uz
         8yHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FyZSmlP4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id i14si255435ots.4.2021.03.19.07.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id e33so3816145pgm.13
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:13 -0700 (PDT)
X-Received: by 2002:a65:4901:: with SMTP id p1mr780094pgs.310.1616164872494;
        Fri, 19 Mar 2021 07:41:12 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id s28sm5943535pfd.155.2021.03.19.07.41.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:12 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v11 2/6] kasan: allow architectures to provide an outline readiness check
Date: Sat, 20 Mar 2021 01:40:54 +1100
Message-Id: <20210319144058.772525-3-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=FyZSmlP4;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52a as
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

Allow architectures to define a kasan_arch_is_ready() hook that bails
out of any function that's about to touch the shadow unless the arch
says that it is ready for the memory to be accessed. This is fairly
uninvasive and should have a negligible performance penalty.

This will only work in outline mode, so an arch must specify
ARCH_DISABLE_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

I discuss the justfication for this later in the series. Also,
both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
---
 include/linux/kasan.h | 4 ++++
 mm/kasan/common.c     | 4 ++++
 mm/kasan/generic.c    | 3 +++
 mm/kasan/shadow.c     | 4 ++++
 4 files changed, 15 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 8b3b99d659b7..6bd8343f0033 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -23,6 +23,10 @@ struct kunit_kasan_expectation {
 
 #endif
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6bb87f2acd4e..f23a9e2dce9f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -345,6 +345,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
+	/* We can't read the shadow byte if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 53cbf28859b5..c3f5ba7a294a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 727ad4629173..1f650c521037 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -80,6 +80,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 	 */
 	addr = kasan_reset_tag(addr);
 
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(addr))
 		return;
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-3-dja%40axtens.net.
