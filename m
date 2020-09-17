Return-Path: <kasan-dev+bncBAABBD5RRT5QKGQEGHVDK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-f184.google.com (mail-il1-f184.google.com [209.85.166.184])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ECFC26D590
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:04:33 +0200 (CEST)
Received: by mail-il1-f184.google.com with SMTP id v16sf960777ilh.15
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 01:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600329872; cv=pass;
        d=google.com; s=arc-20160816;
        b=rxjp3h9AjyasuKUgNt37L1jVWa215ut0VtDRCJXg+3e/dUz9Sdxpl6tmOSyfncjjTS
         klhWeyJ/dMVUU3Ki84P2uKNbmtwJmXlCCO3OPIwvc9u+BAtMO4k+wfp1Nt2frQH0u5Vf
         ui44IfDWKaanz0sykBNDmA07O7pBsOaBJ99nrT7aDKMEVtLQnRbwvB44rKtsjM8QAwgV
         pumq0SObf/h/h9lqGPmF8y39y7w17opb4JypGqJtVTXlembOvqdZWfOAmzbCI/D0hP6f
         POfFAEjVFcwuVnLnLRarAvaZY33UWIvNuwu3mRNhwGcKJRKRc6Cz7hiHSwyW2rCYza+Z
         eETA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from;
        bh=pdgWn6kt+nH9ZqMj2qBCtpsL4qkGKyljaEjoOg6eJYU=;
        b=t5d5MrHbVcQBbmNCTQUacgA/wtP+9gRk++v41Xf8grAyk1rcZYWk4ObgJeWxMEIBF3
         j/8K+bLv24zc+NVcaYXHP7lNrYYCEq4OzzvyN0DeisGHzO0rsXQ6oFHvaDljBKWYWeKY
         yvxCn0YMLxpY/RCdG/HTKC/AvryYu2P970upEXluL2/FtspsMn1Q6kGacDlsYvpKu+TK
         WdsPN7E1QgK+PLFnHojl2Do+fOk+sqObl3+WQGRk9uwZPmRVYyexxGGzcVSu+zwtvub2
         JP4dfYIPwgrYjE+z2CJiJOsyVndSTKlvLG3BRi7mcXHSzWIWNs0W9oyAjyt2SgoAdyza
         ozkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PU5+IVwo;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pdgWn6kt+nH9ZqMj2qBCtpsL4qkGKyljaEjoOg6eJYU=;
        b=WplHf0054tneN5AGFPCQP94W3z/Hq8sDF6kt8RxpfSPiOhmPdrPkoBAEqAbBkaH95F
         pqqJYUZ7FdKUqSnOMjhhobfTUz12wUx32u99c2dH7w/s4bZPBZp6eud4Bv9q+sjmlvNF
         +uYXl/8FtfVlvR+Ao6MLAPSUxWp5kf7fuszHJN46wZY065vbxarZP8PZoAOiiMrNc/2/
         DMd8Vrlr8g2hADSux8UsuUgao4r3V3xpeerO5YF33CUyDbPptt21D5BBbEoeCwRo88vN
         rnB48+Pw6TZqeNFie3U0VosFBeacbVaWEiqK0N3XVE8EBOu3JdkDKLxtV2iB51d5fFzI
         gDnA==
X-Gm-Message-State: AOAM530gOXH63RVDzsk9qWNOMMt7eySo7uFJ5ghlwtEn809BBZv+n7S2
	EKbq6To/4cGyAqK5721/0vo=
X-Google-Smtp-Source: ABdhPJw0/yMJ7VOYu+LisjnmJY8ryJfcHM8csHj+80rxGqscIJ5pnJ+tuoXITpQxaD9mV0YVXFSmOg==
X-Received: by 2002:a92:c7b0:: with SMTP id f16mr25170637ilk.137.1600329872081;
        Thu, 17 Sep 2020 01:04:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:c648:: with SMTP id s8ls196665ioo.5.gmail; Thu, 17 Sep
 2020 01:04:31 -0700 (PDT)
X-Received: by 2002:a05:6602:6c9:: with SMTP id n9mr22089875iox.91.1600329871674;
        Thu, 17 Sep 2020 01:04:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600329871; cv=none;
        d=google.com; s=arc-20160816;
        b=IzRHNgN5srOX0PgGooK+6L3pfyfnJcH0dveKg66/Efq4Bb/Cb58tcnQXylzJ+yoMOX
         f2Bi0QLB38+BrfC+aoORJCPQhcjgydgMSGxf2taMR1sDzkeUThHzQOkWmyNvTlcH0Hjb
         YAyAVszf2amIyZjO3J1Q0qZQQnViTCyyZmeNhYRnlq0Ap3AMHiwDWBlcN+gxp3hLfjSb
         3O3P82VEE1n3RX6q+HHwTKfMEA4HmwFbDZmt6BleMt5tDQn/K6V45ABbmC3VipqkSDRm
         bVPcRbkRUEmvhB4gADEQ1faGNliXm8NHH3SSPJdyAmkhblhkITcJhTEH9nCwA2bBhi2x
         MlUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=x5Rkqhb6ZRtF85IZlSr1BZ8pdGwUd4OikvOx8ovizXo=;
        b=CTHFm+6l1FoSfiMHLW37qnxdY5/+U0/Yf0WTMg32a2Xmd2Tn8vgtMTzZ0SujmClDtf
         JDJafeioFWlIGILZGMLr+7BttKR7URcHFc8hHytiq0S2lxWyP9hf+D2dX8C/CfdawIrx
         x5SVd2avy8v5iEWGlDMpC2EUk8bsCtNUcO2unvfsvMotBNNqq+Xlb1JinNojwkZQg0WM
         Efygb1gipq2e4ybGHSeXlo38a2dVaUa0EMmtqWxIXy88KzHuy0bAnOwHYGCIsxblye4D
         YOevZqxk4uYZAmYaV2fpeiIsLLgwEss8eYujOEtjzUEUM+ZJG217ihXmJ/fidBkYM9z5
         xvTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PU5+IVwo;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c10si285586iow.3.2020.09.17.01.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 01:04:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5d2.dynamic.kabel-deutschland.de [95.90.213.210])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BB001206B2;
	Thu, 17 Sep 2020 08:04:30 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.94)
	(envelope-from <mchehab@kernel.org>)
	id 1kIou4-0051LQ-8q; Thu, 17 Sep 2020 10:04:28 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	"Jonathan Corbet" <corbet@lwn.net>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/3] docs: kasan.rst: add two missing blank lines
Date: Thu, 17 Sep 2020 10:04:25 +0200
Message-Id: <53f6987c1a4b032ff636a95e3fce53ff8bfef630.1600328701.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <cover.1600328701.git.mchehab+huawei@kernel.org>
References: <cover.1600328701.git.mchehab+huawei@kernel.org>
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PU5+IVwo;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
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

literal blocks should start and end with a blank line,
as otherwise the parser complains and may do the wrong
thing, as warned by Sphinx:

	Documentation/dev-tools/kasan.rst:298: WARNING: Literal block ends without a blank line; unexpected unindent.
	Documentation/dev-tools/kasan.rst:303: WARNING: Literal block ends without a blank line; unexpected unindent.

Signed-off-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
---
 Documentation/dev-tools/kasan.rst | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c09c9ca2ff1c..2b68addaadcd 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -295,11 +295,13 @@ print the number of the test and the status of the test:
 pass::
 
         ok 28 - kmalloc_double_kzfree
+
 or, if kmalloc failed::
 
         # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
         Expected ptr is not null, but is
         not ok 4 - kmalloc_large_oob_right
+
 or, if a KASAN report was expected, but not found::
 
         # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53f6987c1a4b032ff636a95e3fce53ff8bfef630.1600328701.git.mchehab%2Bhuawei%40kernel.org.
