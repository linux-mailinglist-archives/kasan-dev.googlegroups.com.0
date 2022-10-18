Return-Path: <kasan-dev+bncBCR7ZZH6VEJBBHP5XGNAMGQEQUBP26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D3D98602941
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 12:23:26 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id bx19-20020a056602419300b006bcbf3b91fdsf9375949iob.13
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 03:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666088605; cv=pass;
        d=google.com; s=arc-20160816;
        b=0KplmYruIz5B7U9HrBPsiE7TU76be8bm5787hd8oAxqcVooPtyHMgFNs61fDYFuIiA
         qqJazGM97QITA9gCxLOB11ZIRbX27+EgmkvMIODvnsrFJbEWHvV1U4biNt6e4LTLB5Xj
         Vfc62UtjcGXk7Uejz95mEpDsBeWApDoYgGnYIXUHXJQL6V0Tb4x1nF+tQefLZgGTtANO
         l0APvZfW+D39uzj2haxC53METq+7nlxK6CscWGo2iFXQAzAp2fo7uvwBhdPie2Mh1hne
         BQlLqxcqI/uQkxqjODrRakLlRlWryE4A5fMn3Xc1v1+04iALFcnyyTZ+1smWiZawKubJ
         fTgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kcZ+odj8sGBHn75n78Yal2MfmwAE1D9aXmUyqRUZAvE=;
        b=HM5nowikhRBrRr89fEZDagJvaL7laSg5tzHxwKR3VWp/9GaN4w+fhpBvn9uaIprpYo
         wmdC9h87qRFZfVMo6O7YwjZgd3Fb3kysesGgZXwaGckrQhg7cqUGwshHENqGkIE6EV1s
         ArEhcrwGtU0PZ8N5O8v8e5PayGkEuW6jDd6oKRUAXeB9ySoBzmazb9OO0x4ZTEKpwh0+
         mjIbDPtmrGn6jstbLwSHPyFYwarRftfUBr/CIH9UiTTX6jd4vSJWIhWEs0Rf6iOK5dtD
         IulAtwhFrIXhwKNuB/1KYthUXvhF4Ex/9DC+l9/CGBhovnCCOHGJ0Owj9wefayDL8r6E
         bZ4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=J0Bt+KMi;
       spf=pass (google.com: domain of ryasuoka@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=ryasuoka@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kcZ+odj8sGBHn75n78Yal2MfmwAE1D9aXmUyqRUZAvE=;
        b=c1InL/TUwjVA9ONnyPEM0ESwXUZ2/kTySWlpgr69G64KSfliuLHM/jQ1aIiW73WQst
         tdjDYNq0pGM33T3t2+UCXaUdAU/21rn05FPyXoz3cimVvPb8L043b2VGEIf6A0IkjZZP
         eRqgbIl/nAAmGu2Em0jKokwemIJ55+WyVa2xl+aQ7djh7hqQ2f0CMvI4q2/jqqEvwS0t
         v27TRo3tPDDV09WtgL1/VdKb/o+QY9FaAdsonaEXwBnnqKJIoNagrLJzOCILKCGMBmYd
         SQDjmuewPO7f+vfRWaXLGdj4+Bh59FcEY8o3Qwv4bCUZT2mH4sYERgl4qPz2J+A5QG2z
         boGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kcZ+odj8sGBHn75n78Yal2MfmwAE1D9aXmUyqRUZAvE=;
        b=7RH4tKv0aBkW+ZerTUvged8pA8aNEMP5Ea0dsehI53SDW1yKGTBX00ilKNUIehGyGs
         uyA47E7j2hoham1NwFdKk9AQ3I8z8rNEIUYAklH3r7IOSngmAGw9iLFxG6ch/3BnwEsN
         D4LDrEFG7uFeWZEzpNcDi7G7WM5DPuhLzavRZXPC39mgxLa3PZt3IbuZO8uIGFeFJKeu
         3d0b/UOHNJxZeTwLKKfa9LC0VDsb6JeuLP+0G0JMVPjVGnhPCvArsWwajJ1BddVcfVyp
         RBZEN7BKIu7xOXdP7MxU9akTQUA6avZnYk1GwiLN/hhEApVtkOmZSlXoUASoxzcijEnr
         30ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2P2skItEefy/KqQJJVH4wcexIiqobXT4HY55OM7obEmF58O/GZ
	yKevp/cs4RXamFyqbKV0tKQ=
X-Google-Smtp-Source: AMsMyM6B78hYg4Yc8YXgtKQv9+8jTXg8NiYEnK0J0jUao2Elv2vXO/lTZJJtMtQR3wmNzXOqwfRekw==
X-Received: by 2002:a05:6638:dc3:b0:363:da23:bf7 with SMTP id m3-20020a0566380dc300b00363da230bf7mr1495984jaj.30.1666088605472;
        Tue, 18 Oct 2022 03:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6119:0:b0:6a1:2dd3:4d4d with SMTP id v25-20020a6b6119000000b006a12dd34d4dls1873057iob.11.-pod-prod-gmail;
 Tue, 18 Oct 2022 03:23:25 -0700 (PDT)
X-Received: by 2002:a05:6602:13c8:b0:669:c3de:776f with SMTP id o8-20020a05660213c800b00669c3de776fmr1201665iov.124.1666088605037;
        Tue, 18 Oct 2022 03:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666088605; cv=none;
        d=google.com; s=arc-20160816;
        b=nKXuDWaJ2JFl/ZBmV9ZksU4V8Hdtot/C4bKyJQdxYYIuxbSkww3Al/XVvd40athUV0
         r5tvOGR8GJKrEmLKs2MvZCkk/PyjsgRmQMSs0lDzTYaFyny8CfpP+CcdAH7oXVphavOY
         K1pQdW9Ug5SnZDhRChtaYijLivebxc7sZ6E+mPaZSQkDXmINtkcWLCHR6QROWoc3UIGX
         Ffzalz9YgmpHNiPWFtH8PBpACMOwn4IUNs5K/1iTWJgUE3DZX0Dl+/7BkNLB7MHYqBOO
         tFp4egSXGoW1qWbyoeMKLgNoom6ds38XVj3ly0AvnTnIROrl75kcvT1/8ojCmoQCNFgo
         n7lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lGc1brklA5v9OUHTBe6S3k3fA4Qi2pTlNeYEp6W+HVI=;
        b=wAFckgAo16eqoWMEUowPM8da6NMhHnilahZNJwe7pQ4azStt+CMJo3AmPLzafwqlnz
         UMUr96q8W8NmTnr3brEISZGnQDf61RS0xRZR87FPj4cyjVJLnPo3E9PX8NNO3H5eNO1P
         gKVcHmUAnQENSSsvQ8C/T4ZzDqApV64VpWNmIN9IhDGxQO3rPeAfVhXckPnA5VS0IWku
         NbeEkBi+id6kqoG4cXh5UJKFhkoNdZGLX9aV6yjOycbLExuF/b2cG+FwI0lMj3i6acqs
         fQpmb4/Y9nFq3wSUCJezl4EfJybqRloK0Fu8Iy7itJJsIAanFc2WOyPdebwAbvVB7GDL
         ZpPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=J0Bt+KMi;
       spf=pass (google.com: domain of ryasuoka@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=ryasuoka@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id w8-20020a5d8a08000000b00684e0ad0804si407704iod.4.2022.10.18.03.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Oct 2022 03:23:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryasuoka@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-pf1-f197.google.com (mail-pf1-f197.google.com
 [209.85.210.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-195-qvtmVXErPlWf6R7WEYicuA-1; Tue, 18 Oct 2022 06:23:23 -0400
X-MC-Unique: qvtmVXErPlWf6R7WEYicuA-1
Received: by mail-pf1-f197.google.com with SMTP id n56-20020a056a000d7800b00562b27194d1so7584730pfv.19
        for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 03:23:23 -0700 (PDT)
X-Received: by 2002:a17:90b:4a8a:b0:20d:8a4d:c2ae with SMTP id lp10-20020a17090b4a8a00b0020d8a4dc2aemr36943056pjb.179.1666088602213;
        Tue, 18 Oct 2022 03:23:22 -0700 (PDT)
X-Received: by 2002:a17:90b:4a8a:b0:20d:8a4d:c2ae with SMTP id lp10-20020a17090b4a8a00b0020d8a4dc2aemr36943033pjb.179.1666088601967;
        Tue, 18 Oct 2022 03:23:21 -0700 (PDT)
Received: from zeus.flets-east.jp ([240b:10:83a2:bd00:6e35:f2f5:2e21:ae3a])
        by smtp.gmail.com with ESMTPSA id l5-20020a17090a4d4500b00205d85cfb30sm11173373pjh.20.2022.10.18.03.23.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Oct 2022 03:23:21 -0700 (PDT)
From: Ryosuke Yasuoka <ryasuoka@redhat.com>
To: elver@google.com,
	dvyukov@google.com,
	nathan@kernel.org,
	ndesaulniers@google.com,
	trix@redhat.com
Cc: Ryosuke Yasuoka <ryasuoka@redhat.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] kcsan: Fix trivial typo in Kconfig help comments
Date: Tue, 18 Oct 2022 19:22:54 +0900
Message-Id: <20221018102254.2424506-1-ryasuoka@redhat.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: ryasuoka@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=J0Bt+KMi;
       spf=pass (google.com: domain of ryasuoka@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=ryasuoka@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Fix trivial typo in Kconfig help comments in KCSAN_SKIP_WATCH and
KCSAN_SKIP_WATCH_RANDOMIZE

Signed-off-by: Ryosuke Yasuoka <ryasuoka@redhat.com>
---
 lib/Kconfig.kcsan | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 47a693c45864..375575a5a0e3 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -125,7 +125,7 @@ config KCSAN_SKIP_WATCH
 	default 4000
 	help
 	  The number of per-CPU memory operations to skip, before another
-	  watchpoint is set up, i.e. one in KCSAN_WATCH_SKIP per-CPU
+	  watchpoint is set up, i.e. one in KCSAN_SKIP_WATCH per-CPU
 	  memory operations are used to set up a watchpoint. A smaller value
 	  results in more aggressive race detection, whereas a larger value
 	  improves system performance at the cost of missing some races.
@@ -135,8 +135,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	default y
 	help
 	  If instruction skip count should be randomized, where the maximum is
-	  KCSAN_WATCH_SKIP. If false, the chosen value is always
-	  KCSAN_WATCH_SKIP.
+	  KCSAN_SKIP_WATCH. If false, the chosen value is always
+	  KCSAN_SKIP_WATCH.
 
 config KCSAN_INTERRUPT_WATCHER
 	bool "Interruptible watchers" if !KCSAN_STRICT
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221018102254.2424506-1-ryasuoka%40redhat.com.
