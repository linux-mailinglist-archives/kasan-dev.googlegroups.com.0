Return-Path: <kasan-dev+bncBAABBZ7IVLBQMGQERE6LQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A414AFA6E6
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:45 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-735a86e8e0esf2930403a34.1
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823464; cv=pass;
        d=google.com; s=arc-20240605;
        b=lF+Pd8/PLgi5Az3xuoygsT3UotrV2oI4WlI9aqRWCFvzRqORl9RNULhyky6u0OwSka
         u6Oj/nHIS2ivZfXUa03vUKjCUfqYN1uma34n/kNoyYD9ZDQ3/yanSyf1031p4kivphy0
         AQnvHnti/MatqIUAWUMqGw9Q2dmoMtTtmTlUhFV+Gwfbse0ahcYWWbQQPJUkkAqzxAY4
         QEgIKBAbCee36QwgrM8/mGZcGA2jtZQ4IOPLDco/UVnCVBFpJ79JVcBUAipTGCJyfAj3
         HMt8nm8cB1J0nj6+PeUlM/rPv2vurjwYtWavCvYOPjCFHLEJeM8bZNud2EP34dlTwBhM
         NkYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=b2ENV/cS3itqUC4RjKkEsfyHYHZk+TmjzXXQKy3dh34=;
        fh=OGVsytKRU270h3X/aARQAJec5d+C4oKlYdvFlRSmea4=;
        b=KTdLVdFn8Yj0v9dkHFw2vFhIgEhLq/rWp0q8ppakiLrbaqOKAFZ5EjOy0RE0rm6ATo
         ciIZPCYb+IScRtVYg6lf6KI8RzxMUtZe95YNAU2v5JwYf/oEgPRflqVVqEnpAuxi/zjY
         cqpDmcToO0GTp1YxaVyqQM7sNL5UzfVcFhLwLZrv0Dy9Ypy0yWR8Rnu3QODL8xmf6TYY
         slRBSjueZf2X/mUu2P9ZIZ+S1nmxU4Z5+qQEOPvs1uUkGbdKGbA7fFUVXF3vTGBjs4Ll
         ZmZy7B6C7QecOx20PxRs0lAOLlLWTWHYglVt4p9jhFq6+M10FQvS71GuT0Jd6AHsVG4N
         h5ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XlbC7Oy6;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823464; x=1752428264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=b2ENV/cS3itqUC4RjKkEsfyHYHZk+TmjzXXQKy3dh34=;
        b=GlvaH+kwRpZNl8n3d9yYOqHmjfClLZn692anWG9gr36rSm+doRwD5zJWmu5CNRBxeD
         GSiK9v5H/Q5NjylUrOkudiQ+HQpwl1DnVCSBzzV8vilmCQTDXFyOpdgHrkCLMMJ0ogjo
         yE+skbH8KYBOBq9/lxeJ4Jd80bOuLWNiVmA3vwBN0sZ+H8nlcg9EBG/fTpqlEY67zkYw
         odCg6nEALSOhg5lSeErV3w8Ts29+mPp7kkb1K0jt5aBNKXUxKoH7Ua1dXp7h7sYaZU5B
         8bSffF7fso9qSiYNmuSDuGLdZr7EVMJsoEV7Ei7HZVzLXwQqG475In9/TzP4RNKVA1Ty
         Zyqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823464; x=1752428264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b2ENV/cS3itqUC4RjKkEsfyHYHZk+TmjzXXQKy3dh34=;
        b=OlVpEZmbadLCqTpO45a243EcWPS7ys4kvVMtSBE6cZGfurBNn+A7cdbbESpKRkFzoR
         zGybgTXws8vE9YDNYnQlMpU2pF37BGXm+UqB2QSl+I+u8/XgmUgEZKMILAqlSq8jH2DU
         9wfQSvpOAQ3n7G5n6viYVRQvPudNoeeQzOx/CiteY500pPqDpsco51i53H53LLTr3ypt
         7cITW2/32CcipMWhVU/xJQv395GdXg8lOutddhbPy19CWE4DDkpcoDlBiqVYmb+KYt9K
         Fxr+gHkGdv67kh66c4XvHkFAdIoPUfH/w85RkW48oYOCYx6sTixcDwViBdixCnwEBcun
         b4Uw==
X-Forwarded-Encrypted: i=2; AJvYcCWKj63uLf8Lf2oAi4u7rjt4yi7fwqXGo1j1pxKblEPnf7UaUp5e5eLAPlFU4uQy+E8mNIz1wg==@lfdr.de
X-Gm-Message-State: AOJu0YyCgROhTpcK17XinhYg8e8NII8VLH84OlzUs3zM7kKzzGIDkv+g
	lB2K6KpMWyKMrldW9G2n2WKM/LA9BmWEKBdfXTORx+8JnWtPYrzxWdjl
X-Google-Smtp-Source: AGHT+IH2BqosvRYnAncfSsSOj12ikYkZIN9yKuLkoS2MJ7v7ytsvOeXxUu2vZp4K72srQT/n9obBug==
X-Received: by 2002:a05:6830:4d86:b0:73a:8a8a:5151 with SMTP id 46e09a7af769-73ca66dc922mr5904781a34.17.1751823463836;
        Sun, 06 Jul 2025 10:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXw8ErAp1NlduKy3GnIi503LmWCDMv8+WyNClrLVTEig==
Received: by 2002:a05:6820:c312:b0:611:5786:dc6c with SMTP id
 006d021491bc7-613955c5180ls844027eaf.1.-pod-prod-09-us; Sun, 06 Jul 2025
 10:37:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4NU1bfI1DWpyRFibvelVkvmgtKc5+J5CHrtY4wb3ttUWKtIhV2VYN1FcrYNx+50kCTJkAgLxqnIU=@googlegroups.com
X-Received: by 2002:a05:6808:e8e:b0:40a:54f8:2ca3 with SMTP id 5614622812f47-40d072766d2mr6717689b6e.3.1751823463025;
        Sun, 06 Jul 2025 10:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823463; cv=none;
        d=google.com; s=arc-20240605;
        b=eWTO2ylF9Kn7YnBBgvmIHnskUiMzCLT2Q4B4RIE/8Q+m/Q23iuMpGME4BvJIV8SSh3
         XwsoH7rbsiQ65kubxb+J8ZYUaKN+QMf7oMtLSEl/jf3Mv/CDJA3JMM5JKk0vj/euIjJF
         W12Av2pMrv5uC6+crRUKwanRDJEUzwe83gO9sIZ2a9JRRtjWVV0iV8ozJiBS7TVY0mOF
         in1FsN9IXhD0uxgvzoWJN5X2Gk9VMquVrmHHaXuVc1YN4zgZOrs9TqAgtrXcEvsxhvuB
         GEFT/oyyj6bwWk2BviG1eQ/AKq88S4um8Ov71S2heBX+/tG6gSz5A2k6hN5cgyxFy0Rl
         LXzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FYutDAAXQ+Ktdwc6o3MpYj6Q1MDXdY50oP9MU682I1k=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=ftS6RF73uL2ptMt2NWMRfBhtoCegfe6nc6aF1d8vezUdfjm5g4rKYLD1Snt/gWog7z
         UGtRXnqiEUpHOGu56nNO3GgdLvJkgq8bLLMXowxPUWkOjMobOht4RLG5mmbYirpoctL/
         rIDWd0fzhhymsqzPCUhZ/8qTAi9NiEejveYLuvCtbd599QX8Pbv9ClGNclhFPQ21uNKS
         abVdizCxzdY/lSCZNn2aBM77EN1kTjMqzCUSXdHF4tMGvfjVxEujD2Krv4fNWeIcQ1zj
         mU0jpgD1pBBERpXtPotBf2Kr7HAlLk+XUOUfdKjsV8xbnqo396hYaiuKScvaziGTCnZx
         hDSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XlbC7Oy6;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40d02a8a77asi256564b6e.3.2025.07.06.10.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CD22C5C476C;
	Sun,  6 Jul 2025 17:37:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7D26BC4CEED;
	Sun,  6 Jul 2025 17:37:41 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:40 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v2 4/5] array_size.h: Add ENDOF()
Message-ID: <5331d286ceca807bab76587127a9491c807c9a2a.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XlbC7Oy6;       spf=pass
 (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

This macro is useful to calculate the second argument to seprintf(),
avoiding off-by-one bugs.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/array_size.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/include/linux/array_size.h b/include/linux/array_size.h
index 06d7d83196ca..a743d4ad5911 100644
--- a/include/linux/array_size.h
+++ b/include/linux/array_size.h
@@ -10,4 +10,10 @@
  */
 #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
 
+/**
+ * ENDOF - get a pointer to one past the last element in array @arr
+ * @arr: array
+ */
+#define ENDOF(a)  (a + ARRAY_SIZE(a))
+
 #endif  /* _LINUX_ARRAY_SIZE_H */
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5331d286ceca807bab76587127a9491c807c9a2a.1751823326.git.alx%40kernel.org.
