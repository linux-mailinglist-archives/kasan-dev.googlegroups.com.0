Return-Path: <kasan-dev+bncBDT2NE7U5UFRB6W35D5AKGQE5DUF6IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F9BD264732
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 15:45:31 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id v67sf1717271vsb.12
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 06:45:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599745530; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtXrgx3L2Bbz8GJPF0vx+GVxi/MVMrZY1+oxEldBMimoq+hlCTQ9qOSieNThyQpy9K
         RTdktSWdnmzsRBnASFX7NjMcsbeV3IS3u97BCUQQkrvpTuOzjYtZmp6DATE4EiZKY/fD
         dkxUg3KV6t87+CzBYv70AKAUpBEE0neF4qd2NGvKc805xeocEzbvwn4WvYvFQDUKVtDV
         lFkMxets9IkawdFanMPv9giEl4D2aW6JpjvnhRSotBn0dasT2L4A5mPYuy+C/fZd4Jjh
         w7DqBUZ1D/sAWQ9pawU4uwSRFPdUQzrBXyV/1pcT1nI/cflTyVRPYvvMW1T+R4arUS55
         rs6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=o5qam4NWUgWXhAZw/zROWjCxg3/aIpYYtcGFhdY4oMo=;
        b=ZbXx9zc1AG5trbberOaRnuu0mPY26NlIYTtVuzRo4tmjS/0BHzmOou3/aSr2ztNgdH
         3ERRIkDE+4zbqcvDkTP2pWm8bkWaXSduG79iiykuEBYrGoMd9lw64mga+hYM2T9TMo63
         P3inWGrrZ+JJqbxtQoGt60yzNRYxoZ76L1K4A9qbaQcPVvsIR7x2Rtibti6j8dsFZuPa
         p30ZqeUBFTCTOu/yjjadBwBpi6g69xKgR6HwTzgZvEKYXDuTKTZREZQoV7PuEDAV7RD+
         QysLCuCLrMe509xApZeiJOHp8VHT5+ihfeqXrWEiPjanw30OgX109vWA9smBds2xld7W
         pT+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=bN2HusAT;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o5qam4NWUgWXhAZw/zROWjCxg3/aIpYYtcGFhdY4oMo=;
        b=CGlfl4tZ8Zw9q5j2zs+sPdkziyqC+nL4/WEQIZ+UngrTuDCaREVDG9PC49CLhcXD1k
         LiRVWQ8SNYi2gaV9gNlQq6vJtOTVcM960eTIabZyHnxRemFoIcQ6TS+xRs8Horg7XipB
         bBoMX52sk/7ayLu8diOTXYC6a3bNeAAKzUkaRpRT79mLufNrtPTItj3+cOrO0x9Y0jSB
         btWaaOBcbTGNqjd8WAOrU7UhgrXItCQM6zq74rpOtlUPPqfDjXwv64Guu1lzyPUEoz+z
         jlbpk8R73H/NspS61ZWpD1honE8VqbKo+Z/fR9tNp/hfmpDPF4iGeiFzpJ46Mw2GL6ms
         Ubpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o5qam4NWUgWXhAZw/zROWjCxg3/aIpYYtcGFhdY4oMo=;
        b=e5t9y/bBQG8cHroA4TuIxK91Oufv4xc5TNpMwIZuwBaiKjxp/EOkz8nKUo+7JpnJgE
         lyV3KIgQQ6BIJ7tn80BAnqSWydzsGLdDRcA/z1FEB7mJrJLjjwk7uACIh/ENi37DzKdM
         kcNUOGK0rKD/FSIqejxEZqve6yLu81IeD09UBysJM03QpeRt1skhDP0OnoApXJoEMN0D
         d538eN+JjYlso/EsmooFG+iN+2bvEyYNnxOwFeuKXSLSZsEJicDLtLTSDu8/yzw9KnaY
         o/sjGAsgnRxpoxiy1ZvkOZaDFupZD0vET+MLV1MlU0aNu8z+fVZDEDAWV1CMjtFVJzju
         RsMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530htaHZaJ1C2Wt6CiY8Q2uuSOScPdsKF/5yLvW10/iKUZCY+6Ld
	zXkfIr2rvOm81Wn6OgIixOs=
X-Google-Smtp-Source: ABdhPJzH+bZaNdQh/Z1N0ewjI+AeYMQvekSaEaE1jS7ym/m56NLEnB9n2mx6gE2E66538aAYzQjHbQ==
X-Received: by 2002:a1f:2cc:: with SMTP id 195mr4016029vkc.2.1599745530245;
        Thu, 10 Sep 2020 06:45:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:604c:: with SMTP id o12ls467105ual.6.gmail; Thu, 10 Sep
 2020 06:45:29 -0700 (PDT)
X-Received: by 2002:a9f:2648:: with SMTP id 66mr3459955uag.37.1599745529696;
        Thu, 10 Sep 2020 06:45:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599745529; cv=none;
        d=google.com; s=arc-20160816;
        b=dBmu9kg4F1P4FY2LKtxccrlSZzerD5ZXy/lnKjY44uZuVHNN7aA1aVxCqqmzWT9Zdm
         qEHTBicmqSNhV9hdO7HI1W9kwY4LtqbVfhnN3ULuGLr2Y/50kiex2ESRpr1yW5djnQEs
         rnQpyYDSXEkH60DB8qM0Ses5QPiTvMjvMjWmHKeZzXNWeDycz3H3d5hdYjsZg64ujXJg
         TkYodeXRrEJzJUNKNNFLlMy7TOtInUeBXlKcSG3hJ0k4NnaTS4o2tENNUNtBej3OzT0N
         uqVq9fr88Q6EDdwm0ehI+4WhhmhrvLK3FzEG8hlFpKNEWXgg9lJILmPI2s11Oc8vQVoy
         3xYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=QXPqbgb/jFPOd/TSdAMnz6TSWN+Q2fIoPVXFknMy17s=;
        b=PPY9lYYy/YAX1hkfkHHskLTP9W2/fqg7k8BZYVHz9b0Vnxz6gOKXAB3ncHiRL9L1bp
         31w2Vko2TlBef5iMGm5WmqQq+j5kMh0EbIvOpGZknAgCTp4PN/e4rybmnjl/jD1a+MtS
         0OL8kFW1MSbCATnADC8QqD6dna8sRNmz5s2vzufMclk21xGYG/P7ojzy7EHbpQ0hwVG9
         JY6Z7NejrEvtBUrrre/qe5Cednl+IYwKRfwrLLQu6ESGFhP4s7EUuK4kmEjfxKa8xaWZ
         tJXph8pcPxWrTkDLWO3u81Iou2NiDdbT84L7fgRHYa0sB2bTUujendqwMmIJj5X4gwVP
         rTdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=bN2HusAT;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from conuserg-09.nifty.com (conuserg-09.nifty.com. [210.131.2.76])
        by gmr-mx.google.com with ESMTPS id t1si279761vsk.2.2020.09.10.06.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 06:45:29 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) client-ip=210.131.2.76;
Received: from oscar.flets-west.jp (softbank126090211135.bbtec.net [126.90.211.135]) (authenticated)
	by conuserg-09.nifty.com with ESMTP id 08ADiY4V001894;
	Thu, 10 Sep 2020 22:44:35 +0900
DKIM-Filter: OpenDKIM Filter v2.10.3 conuserg-09.nifty.com 08ADiY4V001894
X-Nifty-SrcIP: [126.90.211.135]
From: Masahiro Yamada <masahiroy@kernel.org>
To: linux-kbuild@vger.kernel.org
Cc: Ingo Molnar <mingo@redhat.com>, Masahiro Yamada <masahiroy@kernel.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
        Michal Marek <michal.lkml@markovi.net>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org
Subject: [PATCH 2/2] kbuild: move CFLAGS_{KASAN,UBSAN,KCSAN} exports to relevant Makefiles
Date: Thu, 10 Sep 2020 22:44:29 +0900
Message-Id: <20200910134429.3525408-2-masahiroy@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200910134429.3525408-1-masahiroy@kernel.org>
References: <20200910134429.3525408-1-masahiroy@kernel.org>
MIME-Version: 1.0
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nifty.com header.s=dec2015msa header.b=bN2HusAT;       spf=softfail
 (google.com: domain of transitioning masahiroy@kernel.org does not designate
 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Move CFLAGS_KASAN*, CFLAGS_UBSAN, CFLAGS_KCSAN to Makefile.kasan,
Makefile.ubsan, Makefile.kcsan, respectively.

This commit also avoids the same -fsanitize=* flags being added to
CFLAGS_UBSAN multiple times.

Prior to this commit, the ubsan flags were appended by the '+='
operator, without any initialization. Some build targets such as
'make bindeb-pkg' recurses to the top Makefile, and ended up with
adding the same flags to CFLAGS_UBSAN twice.

Clear CFLAGS_UBSAN with ':=' to make it a simply expanded variable.
This is better than a recursively expanded variable, which evaluates
$(call cc-option, ...) multiple times before Kbuild starts descending
to subdirectories.

Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>
---

 Makefile               | 1 -
 scripts/Makefile.kasan | 2 ++
 scripts/Makefile.kcsan | 2 +-
 scripts/Makefile.ubsan | 3 +++
 4 files changed, 6 insertions(+), 2 deletions(-)

diff --git a/Makefile b/Makefile
index ec2330ce0fc5..4b5a305e30d2 100644
--- a/Makefile
+++ b/Makefile
@@ -517,7 +517,6 @@ export KBUILD_HOSTCXXFLAGS KBUILD_HOSTLDFLAGS KBUILD_HOSTLDLIBS LDFLAGS_MODULE
 
 export KBUILD_CPPFLAGS NOSTDINC_FLAGS LINUXINCLUDE OBJCOPYFLAGS KBUILD_LDFLAGS
 export KBUILD_CFLAGS CFLAGS_KERNEL CFLAGS_MODULE
-export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE CFLAGS_UBSAN CFLAGS_KCSAN
 export KBUILD_AFLAGS AFLAGS_KERNEL AFLAGS_MODULE
 export KBUILD_AFLAGS_MODULE KBUILD_CFLAGS_MODULE KBUILD_LDFLAGS_MODULE
 export KBUILD_AFLAGS_KERNEL KBUILD_CFLAGS_KERNEL
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 1532f1a41a8f..1e000cc2e7b4 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -47,3 +47,5 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
+
+export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index c50f27b3ac56..cec50d74e0d0 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -9,7 +9,7 @@ endif
 
 # Keep most options here optional, to allow enabling more compilers if absence
 # of some options does not break KCSAN nor causes false positive reports.
-CFLAGS_KCSAN := -fsanitize=thread \
+export CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
 	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
 	$(call cc-param,tsan-distinguish-volatile=1)
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 27348029b2b8..c661484ee01f 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,4 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
+
+export CFLAGS_UBSAN :=
+
 ifdef CONFIG_UBSAN_ALIGNMENT
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
 endif
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910134429.3525408-2-masahiroy%40kernel.org.
