Return-Path: <kasan-dev+bncBAABBYNNVHXAKGQESNQS7ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7640EF88EA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 07:53:22 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id b12sf7546172iln.11
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 22:53:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573541601; cv=pass;
        d=google.com; s=arc-20160816;
        b=QdczvWZ4mnl501z5HdITRaz/9Sy6ByNqPWfMalGP1nH4cpb3jWmLInNjABAnLVg+nL
         7WEScIoxhR8KYx7n3jBNnpGXQDWKbBELK7BiaqMl/fsLZnXt5FtPys3kIHYJnuoSEeE+
         YQdkHXf7qQ4x0e4v2Dbqzoyt1hUrBthvkJUCXGofzIYxzVjggDRc8B3n48V/7NS8vuKH
         AR3lTHY8vopY8NiKx74wFaH7DXYR1RiceIpEv/W8RcayPJ7qPBJ4Czt7LfEafAExcr72
         szsJCFBNRuiVoNjy6UaQuO+/WnM/Jlir8vOXS8TBHMc8S+8lZL2agsk0AwQ/BXq5QciO
         kCjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=G1YuwgN+jvxwSh4plwET+XuMsaNlCg6RGmOhwmZtwNM=;
        b=eFszVhfpfNISKh7+NgOIgHS+LD9y4+z5I1HganLuS463CuKJn2o0i4e0sY+2FcATms
         uKGWvw/68ejYIbzhgPTtFmJ1t28MU9mC8SbBZXv/7HuXzg2Yrke61mY0Z98BSbvYRsqr
         hMN9xPaEw7nsQd5AGrTZAI6W/Va9BEGsoMi7fEzC4QoES8ZunJxJjGR5q5ec7ec+dXC2
         uRafwWehWi0FB0Xxaj6wHEgnhP1niLKsLYp49XJ54wlPqID+PtMBkRrHlqSk3I2aUO4o
         cJQB1w0+JeOR72SdQl60KWoau9aWWrnx8MuFqEespZOr8Ce+AvobxMeo56iSR5spUGzP
         xY/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=K8jnYRkn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1YuwgN+jvxwSh4plwET+XuMsaNlCg6RGmOhwmZtwNM=;
        b=DEfIsZTzUsQdXyLjeR4os/OvhxPfIai+ExO6Q2Ijt6DSRVU9dNNTycYwvXnCx2B20R
         w2LQ6+mcjny6e79g/DvtGgcdyiba8tkJXyDFt3JaY67eYL16V9hO9xlk/Ebn3FbMK6WS
         s+c7F6l8y7AcOQlr09KDdCpHWrlsh5wtVraTBvsW7z526JHIZk4doUmXJ4sjIaNAPYYu
         Innc15ua4L+GEh5q3AcLUWsraY+pK7Gp0rGL+3uYeCHGQnx613WzwImp5wnwk6oOYF2l
         5uyavk6GKeSg3izTOLzAhuyyPgnFSALd5Q9TO3Om44RXGw2yk/cGCZNohiCQKj8XQGTW
         cCvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G1YuwgN+jvxwSh4plwET+XuMsaNlCg6RGmOhwmZtwNM=;
        b=VWkfM/DsdE4tC0jgj+x1wcpgT3VzXJzuroQFh/GA/1Og3YAHdRv3c0hPuM40b+pdst
         jAqvwLXKEhyaW/TsjZzDH1T5psr+E5BKmck9UunnQ+VqqiJpXbF4u5qFY+GowQIeDnfJ
         isVM/Z01wiHIJqZ0itVlhwB0xmHoCOhh8LSFGYD0/3H629q+svVXLzzai/bNVeUUX6mQ
         0dKSDHRjfCv9ZIxfbV/oeAZ4JcV6kYCZy9VOV41miarAp9hFFCHQMMFmYXglWNHXjsPe
         sbxJwqN/Kwt0WAaZIWVxmBe7W/yCRKTbCPcvnOo9OI8WmlsW8B0hNEfgUsxNlZx4SLdj
         8FZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWK46UHSNDTvx3oFsEIrNz2jMuwDicBf4CmUwX96/2LXzlRZJ2y
	31MpLzzDPbO/Iko3XJ+hBLg=
X-Google-Smtp-Source: APXvYqwu+OPdqAVnU1xcttxEhrNnsIx3htxs4xnd2c72gNJDwRq1EVT8Mo6Kq8OwX5unx0lPkaKRJA==
X-Received: by 2002:a92:461d:: with SMTP id t29mr35727198ila.100.1573541601271;
        Mon, 11 Nov 2019 22:53:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9e42:: with SMTP id i2ls1439454ioi.3.gmail; Mon, 11 Nov
 2019 22:53:20 -0800 (PST)
X-Received: by 2002:a5e:9706:: with SMTP id w6mr5975270ioj.252.1573541600974;
        Mon, 11 Nov 2019 22:53:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573541600; cv=none;
        d=google.com; s=arc-20160816;
        b=zNUiB7kr+F52HhcLiicWa527FF5ibCv0RlwZcnFy8eoXAp0gIMg1vyTJnE5sJGEw5w
         QKHz61ETPEij4MRQJZj2K3g1xQVKpRpTn3QON2wqbUv6Ow4qu4qUGnQqiP6hgZSYOGnx
         HNlpmZVQQKXPypoBnNBmv2u1qLlbbOlu41z5CYhLi2ghUMpNNSBG2SRZWe2ICn1WKPIK
         bXdMLOrCdPwjrU8Hl+wgpCTThAE3jE9nRbm8n9Q+IwucbuqDtrRz86pX5q0YYNgVgX6j
         MuYYWFF8xZlylZtyZVCbomlnOsEuuMdQcE5OCnP4t3WkzOP+n10Lgl4pgPS2y4iJoo2j
         J16w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Ehsd/rqNjquxYwB2rWRhuOLzczdbDyhLWsWEeWLWGxc=;
        b=v+irNbNLzVxTU/IfaBzWd9tn7fHt3voE4i/BnOXoeBPlM4rJPUaMsUMOo+OU4q017H
         +Pr4rF4W7b/cpnwuVRcpncTbmup+sbpIK2HP4qxGMlzeUTIzjEKH8F9NfiZYI94CtG/4
         Ao37LTPa6t9hrtZtuXTTM+LUXgLpOVvJo5IELmFi0pViO529NbIOPcG7AkOCQDhPc639
         X0bCLczXRcAI5MZY7p1ceEGwDIo685vC5La3pd11Czs6u1ScolVVexaYQWMiancTQt+j
         1OaOI2G3b/mDpGbRA07zotKDDe1BE5b7tHDmkhinrLFSnKBKnMgBYfUVJhHm7KUYUbU4
         J/2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=K8jnYRkn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id 3si795216iog.0.2019.11.11.22.53.20
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Nov 2019 22:53:20 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9fe46707aa4d41c0bda62169a4f3ff8d-20191112
X-UUID: 9fe46707aa4d41c0bda62169a4f3ff8d-20191112
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2061064915; Tue, 12 Nov 2019 14:53:16 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 12 Nov 2019 14:53:14 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 12 Nov 2019 14:53:14 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 2/2] kasan: add test for invalid size in memmove
Date: Tue, 12 Nov 2019 14:53:13 +0800
Message-ID: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=K8jnYRkn;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Test negative size in memmove in order to verify whether it correctly
get KASAN report.

Casting negative numbers to size_t would indeed turn up as a large
size_t, so it will have out-of-bounds bug and be detected by KASAN.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/test_kasan.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..06942cf585cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -283,6 +283,23 @@ static noinline void __init kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112065313.7060-1-walter-zh.wu%40mediatek.com.
