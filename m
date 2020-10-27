Return-Path: <kasan-dev+bncBAABBLW3376AKGQEPLQP7AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-f191.google.com (mail-qt1-f191.google.com [209.85.160.191])
	by mail.lfdr.de (Postfix) with ESMTPS id 0603029A83E
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 10:51:44 +0100 (CET)
Received: by mail-qt1-f191.google.com with SMTP id o25sf399293qtt.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 02:51:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603792303; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIFRjH5TLn8cd2rEkplrurvpX6pcNozyCn78F36WbTmFQV5Ua/yKSxXirE2/qBlnD8
         LMla/lstF8xOdnVW24Vqw19Cm3slqkFDADmmqmLfIiEw+z1pYoKtIxdogbwoHGeExIvJ
         rHSiQJLoewMCSGv6jvf/wkrzFNTEDwKsEybpKRqJJSMJ0l2n3ZgyBnILMAup6o+vF1uE
         BgDV6yiswU9KbVSE8Z8HxoTNq+Bk9aDnmgHuQgTn7H6txv+Or2UIUV8EL/aYl3dAOSGu
         +yS9dmrxCwg2HpjbD/6u2jqMLJShyT4bbADJ15tp7vbGp3XRh4LOEnaRAw8xC/Y0kANb
         60Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from;
        bh=VtN9vdHZOJQi1LBEm77IsaKCtjgeu2X6dRBhnpxlkB0=;
        b=Cd6lZ9FufqVS61Hn0uSWIS/IJ9VSNCaqS4RMdNSRUIcx/pU8ejHkCHoPs3evMGztBk
         b8SHgUqs2vpbcSdB7v+UP6/vIKJEkjdG3OfFuqy54EMZNWL9PGeUV+k+5VTK0SwGYyig
         /qzwi/xdfYFqbu8CwJz0lxLoDDRHwm16IMsYOF9la7cq7mjYQQnKgqCgxp1txywblATb
         OMRxFlF4vgqPZbDHxQbg3HM2C4rCbKa+1MNWKxeedHQQbmOJSLNe1aGf7gCLnSqPuR9s
         PL1TuEoAaRrh5pe2KEXPlmkxYwgkVdHaGYXK8FkNoLH/y9HDKVOKNfPLtLDVWP2QQoQc
         XsUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=shzhb+p+;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VtN9vdHZOJQi1LBEm77IsaKCtjgeu2X6dRBhnpxlkB0=;
        b=rnAmpzJrgszdvCG3BLlPLCt6IcWSAjSgLWZtabWDABGnBf9zxRLOQmFk16GhO2qrA1
         ++ttDjhJ0L7s6v6i4Uwpnb1xqWewTECxSvS4PqQcZzhctHjF5JRs3FV+Jrlps4OoW2vq
         TfqNleDwy6XHW5Ou8yLKxbmMiogJaO1eLCsw7JB8M/3July4O/sYuGGUwWDI32Q2nIbg
         4Fz6iOzMSGn3Wxnxi1MzV7YTaRUkbdexOYVH0+TcGvQqoi6a5wZ2cH5h+Tww80gRi5kc
         seqfWQcP8qCprtyjGM8u/LZazuqb1vEV7ZrNZ7MgOW2UcZVt7TyjSR7alec9ym3MmFeS
         C+og==
X-Gm-Message-State: AOAM533Ks5RIIWJLN79Gzaf/bLVz31K3aC7WGeJrtiVyq6W6Eed/RzlR
	kkiWUkRwiuvXRv7nBD4/944=
X-Google-Smtp-Source: ABdhPJwycROUz2b5W6r0Fc4ilHJNarpkDk8Jz9hso8roHFnUyiubVJYDsEWXXflzhlsiI4wMZUpvpQ==
X-Received: by 2002:a05:620a:ed1:: with SMTP id x17mr1180388qkm.322.1603792302924;
        Tue, 27 Oct 2020 02:51:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2c09:: with SMTP id d9ls312539qta.1.gmail; Tue, 27 Oct
 2020 02:51:42 -0700 (PDT)
X-Received: by 2002:ac8:5852:: with SMTP id h18mr1147477qth.345.1603792302455;
        Tue, 27 Oct 2020 02:51:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603792302; cv=none;
        d=google.com; s=arc-20160816;
        b=B4vQ57RiJcuqKHecqpCSxymTD9Zg6MkjEXr0ArDRW+RKimS18N2Faf2K9n0heniZ1U
         y08KzeDIlTyu4rZc/r+Zxic4JlASJHRGfUC+FGTLcVX0IF6+K8C0bcdonD3EIAGEUr+A
         XMnH0Xe1zSxmcPryMQg1d0zgzkzBjX7l9Mv3BksJn3b66YRN5LuVzGtweTbjuE3smYpG
         2afsRZuk1MLy0O/oWcKW3KVcJM7Dkg0wBf4ZXxJkwZkOPY7yfJ1pwfmTYoNF+MASX4bQ
         plxMSdJ8XSZQwyt5Qg9hb+ReZBFFoPUw6o5jA3N+P+z8Zr3N6STiwSsrPlt6gfvrjj7E
         QbWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VjyfrCRdtpFGYB2Yo66fT4YY0ayYElgCncNCHIGB/8c=;
        b=h3ILx8OT+IPI2qDTR11io0+fvkDJe29r47RAyaRzGiKIvkFPKndGMTG8/hfDgxUIYf
         PEKsD26R7b8i28O5xTaaOlN7C2Ihv9j1qAQ69QHNXfx6Dwby0qjNP+175OJvOW/ZnabP
         wHKf/BmCsf7SOQ/m52BFRGp2aeMhE6jXfPFoD22AyHbLJVreA6MAym2DH4tQWLLLzhtO
         XSk3+R3AYNVOuYhQtgod2SnaeZVlbma/LOMXtuqCBUTpDA9V8vPq8t1D4SF+wNTuHfiX
         6wMKbO5eBVctnr44Gy0iGw+Bh47kH8o4hFAjU8PM47eQSl254kCVqBJsn5KJrd8NaflC
         Jqxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=shzhb+p+;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z205si69117qkb.1.2020.10.27.02.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Oct 2020 02:51:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5af.dynamic.kabel-deutschland.de [95.90.213.175])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1875A22282;
	Tue, 27 Oct 2020 09:51:41 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.94)
	(envelope-from <mchehab@kernel.org>)
	id 1kXLdj-003FEe-2A; Tue, 27 Oct 2020 10:51:39 +0100
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>,
	Jonathan Corbet <corbet@lwn.net>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 05/32] docs: kasan.rst: add two missing blank lines
Date: Tue, 27 Oct 2020 10:51:09 +0100
Message-Id: <cd6c4280fe26b07f2c5e5ed2918e17e88bb03419.1603791716.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <cover.1603791716.git.mchehab+huawei@kernel.org>
References: <cover.1603791716.git.mchehab+huawei@kernel.org>
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=shzhb+p+;       spf=pass
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

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd6c4280fe26b07f2c5e5ed2918e17e88bb03419.1603791716.git.mchehab%2Bhuawei%40kernel.org.
