Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBNG4RHZQKGQEMV77IKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6718C17C1F4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 16:37:25 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id j63sf3764277ywf.16
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 07:37:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583509044; cv=pass;
        d=google.com; s=arc-20160816;
        b=osPXdJrpyk1HW6wLOm4SL1rkcNG5qX/lzcZWMVPOzzBGl0/V8E+3DvPhtp6UmJKrxy
         6FcN89n3yYKDcKic27qc4Pp4qkG3C06LFaR4Y4Ye1o8PqjzygoEPI93EPt0bHiYJDsXK
         Ev9iULcJM+dFOYGvWqOuyjLuHoLhpVaIHtB1BUq5LnGpW0n0rTN5O2WC+focWbXrCCqf
         Pj9A9Af8fLZLkBT3ITLr/1oI+NCROwlR5VSBk71E2CMCK7lEleN6DEYEGOkCWY/u+Xh5
         CSAeR3DP4OWnXCp2GA5P2Mb1pBSWLmyIy7tjdIrCwD/pU0YR6TGFybY6v/ZrQMNhraTL
         pbjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=uWcLeTEnaoQqOipW6MShGu7iXnWSXvIWg9tMzPT9eRY=;
        b=s3AFcatM9hoKKWCGu0Qbk/7j0S+JD3bc/TkFmupWeZPkSgj74STPlFuAmyGMfKxwDN
         o4XDoC91JcBzhyF05Zsc2zMRZ+RuiH7T/U09y2zApyi1XyRT/7MzIaKhE7EoPniAmOwU
         z8Ls8GPIJZoN87sluonlkiYWKeu9vVWD1J655+LgxeeNtaLNGZxShOBnrx2GZNUjSRV0
         3mWL8feqz/FMWkjO0E89GjUTl7+fN+6JqjXkH7WAnWSRJM3SA9OEYHDGCqAEuKkp/sY5
         Vjkbvw+DzhWSAg0ttMkvCKbhBokoWzbqIEidhOe8frUi8Imp1Ifemm2xyklNnMuqNocR
         LXZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=YAqiAObC;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uWcLeTEnaoQqOipW6MShGu7iXnWSXvIWg9tMzPT9eRY=;
        b=C8SR4is7+DfAyfV8ReMia2Hxk0oe7c86dzqPvGOODl/QIJv6UJIQvv8tDdzSBTEemd
         g/fZjGwlOLNBQb3d4DWbiVYkQ5DPSCfTdNJVz8BzQai4nWD26r56xgg/jsRT5wQRpNeT
         P9XatSIrHS1XKEbBRiL5mPXBxXp1mFU6mJMVNEjug4J0vOVJ41xyN5wfZQuxaiuN/16V
         f3oVrPCjAqd5CuuaPxjEImHvdwa7NXEg7fWS435QXkcnk7GVSUs2/LNR9OKGX8XRcXuV
         D4AFaTNszKiTgnw33bEJ3YDUq5R2WhzLqMTwmqhlyA8P+QWdADHDa0ehtTIwgixm2FlJ
         KeeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uWcLeTEnaoQqOipW6MShGu7iXnWSXvIWg9tMzPT9eRY=;
        b=o9iyPmrkl8aQQ+WsC/7thbQLY4/bm0b05KSxPtiZIwUpw4k9B3BtFF/ntxP2msIgwB
         nkgfjBOSCt0gjEV87HrSH8PXdRDCzG8SfX7OKiJRa8cENECubK+RU4IY+d8Iupu8MUIP
         6PViq/2r8pP9WgFMfhGe8tDBGhIWmHBi9SpaGliHwgmUqY1dP5TPNNGd9rVHRU/huZ1n
         HaC3Yzn/ow3KFOUXODCAatxZm7FMgZF+aJKgp5wpnrmC+lLe9wtFndN0yE0T5/SmPY+N
         6wLcDETzLqyT/1DSCT+QyajgijLpmQglmSpbT0ejBgnjDp3HgvR7Ci2GMDm9iw7JAqvm
         8Cmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ25z3uebzkl9rS9WXoingprf06Ni9quUQwRrljS8ATmA2zRaiLX
	gxDSymWkShGW865M/CktlNE=
X-Google-Smtp-Source: ADFU+vvZlwrkyGwopn9VvOqDPmNHypnFmRnZH/q4Etkd7L4bfyebxZp81/+lUhIPBvTIug5KuyTvWQ==
X-Received: by 2002:a25:49c6:: with SMTP id w189mr4396691yba.438.1583509044401;
        Fri, 06 Mar 2020 07:37:24 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aae8:: with SMTP id t95ls606487ybi.8.gmail; Fri, 06 Mar
 2020 07:37:23 -0800 (PST)
X-Received: by 2002:a5b:886:: with SMTP id e6mr1791991ybq.23.1583509043597;
        Fri, 06 Mar 2020 07:37:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583509043; cv=none;
        d=google.com; s=arc-20160816;
        b=xzKdXfZaMjka44onyAhfsxmp4YYaFUdNywZeoPAPJkuxVNuplBv7oupdCeapuQT80q
         KTYdrGvl7tNvj0AowQaIuxbmo6/JJXC3xprF5srbQa6eVWrSdJ5l5fk5pCj6mY8mKnWc
         1Bb0LXgYmUWXgwWzsuRnhW25aCJZGfLLcvfICF594r+hBjq+T2vYyXN4HbheQehPaPo0
         8oeaIW+9VTIK+JHG7/1hvh0rtcYw1eMYwldHjb0/IIfOBJo7glU5jAz6ynt6f63PAo3w
         wYT8M7ZB5bZm5Yx6R3w4l2qu8xUacDkeiV0XiqAnp9MhD0iUGykQtdkXqZAGMKF8Pwb2
         kMPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=j6sXql4oSXT6Q/ws5TYxgRAPlqnRvsWRJL+OU5ImErY=;
        b=L5PiIL8efyDr6kxMSFfyxelQEaqkADOjSKXKhc52k1ARzjUY/NvO4xmALigesL/Y6j
         dyN0Iq4x7XQ/F7BtH5fxM7u7SaKGakUJUC9VEXS84T+ps+fhBYETmBhMTXOQarVuOmeC
         PmdWDGz8fGd+z3xGiE412ynPmxUtNxcfmqCBO4NZHsc7IwRSX8cS2uwgz1GczgtVQuZj
         bh2CAQh/PNYnIPovDp5c1pFxZMmrboNIg3GOjS9X5oiKRV/qFJd3sUEyN34LbxbVbu5z
         SZatJkIE2CjOX3VQ9VNV6I3fdNRkVJQDQvuxkYbBboqH6ssKxpIaDSQtwu5jhO6PjAIo
         EDzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=YAqiAObC;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id b130si179384ywe.2.2020.03.06.07.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 07:37:23 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id u25so2687414qkk.3
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 07:37:23 -0800 (PST)
X-Received: by 2002:a37:a80c:: with SMTP id r12mr3278127qke.241.1583509043047;
        Fri, 06 Mar 2020 07:37:23 -0800 (PST)
Received: from qcai.nay.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id t3sm16038837qkt.114.2020.03.06.07.37.21
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Mar 2020 07:37:22 -0800 (PST)
From: Qian Cai <cai@lca.pw>
To: akpm@linux-foundation.org
Cc: aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	walter-zh.wu@mediatek.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH -next] kasan/tags: fix -Wdeclaration-after-statement warn
Date: Fri,  6 Mar 2020 10:37:10 -0500
Message-Id: <1583509030-27939-1-git-send-email-cai@lca.pw>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=YAqiAObC;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

The linux-next commit "kasan: detect negative size in memory operation
function" introduced a compilation warning,

mm/kasan/tags_report.c:51:27: warning: ISO C90 forbids mixing
declarations and code [-Wdeclaration-after-statement]
        struct kasan_alloc_meta *alloc_meta;

Fix it by moving a code around a bit where there is no strict
dependency.

Signed-off-by: Qian Cai <cai@lca.pw>
---
 mm/kasan/tags_report.c | 22 +++++++++++-----------
 1 file changed, 11 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 1d412760551a..bee43717d6f0 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,17 +36,6 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
-	/*
-	 * If access_size is a negative number, then it has reason to be
-	 * defined as out-of-bounds bug type.
-	 *
-	 * Casting negative numbers to size_t would indeed turn up as
-	 * a large size_t and its value will be larger than ULONG_MAX/2,
-	 * so that this can qualify as out-of-bounds.
-	 */
-	if (info->access_addr + info->access_size < info->access_addr)
-		return "out-of-bounds";
-
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
@@ -71,6 +60,17 @@ const char *get_bug_type(struct kasan_access_info *info)
 	}
 
 #endif
+	/*
+	 * If access_size is a negative number, then it has reason to be
+	 * defined as out-of-bounds bug type.
+	 *
+	 * Casting negative numbers to size_t would indeed turn up as
+	 * a large size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 */
+	if (info->access_addr + info->access_size < info->access_addr)
+		return "out-of-bounds";
+
 	return "invalid-access";
 }
 
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583509030-27939-1-git-send-email-cai%40lca.pw.
