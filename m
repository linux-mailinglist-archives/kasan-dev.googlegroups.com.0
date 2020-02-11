Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYVBRPZAKGQE67MCWMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 656FF15944E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:05:54 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id d21sf9686827edy.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:05:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437154; cv=pass;
        d=google.com; s=arc-20160816;
        b=aVsTTKkqV+mV1hhF2KTZ9591lw17IZHTkiz5E3jr6KO4qCppVunDJ5ZL7wTTg2HYTB
         MGzqAqNr5PrpF5GSsVQwTYiTpZ13KbgmLOTEHfwoJQWgmKDKxAPaUSAO4R7Q+2EU82Dg
         yeIa2laO8lHQJrxdM0RFvGcJjNLmAPkihSS3eBFk+sz1uxXs4a335Uvvq8PwBRMpTEAf
         lWVaTWTIrXLpbIv3HIAOIgtlDfe1P+MXuvoCPzF5gj8dxEYf7KI7mPK1wtWhWcv0YfV+
         6xQn20c8zqNQjmOgxpUPU5FC2mcfIbqLIw4j5F8NTtmXaY+0aWgkYd1UkxEFU73IR5vr
         sEgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=f69WVsTxVbTZpC9j9TnDjGj9PoGXvcdZZAa/G33DVjc=;
        b=rdZmrdndRkBDOMv/rh7YVcrNvdr6mJLG3ZyOX4cQqg/ir43cX/C/pPsYSl30puXGxx
         fNUVd4+HolHkFl0lf0ORY1RIlmFiW+LMs0iI44ZPHBzDSh7lwgyLGNIr3QH7x0EXXE0s
         eCuNtB/8Uiqa0QUmShYulBA8AOy2pC4OaaoB97uR98nTGRS/Im8B0r6Br9Jb2J50dRXZ
         z4fQnBB6Iya5g4k97/PpvbKfIIJ8QTQ94K1FqQWLHSLnrUKwV9Tk/WZd2G+VBYbO9UIN
         ULWFVxN1ocrgvKDQCy16gNeE81F4H1R2wR0l892Z7IGpu2Z8vqKx29hKCjFpPgCRbe9D
         jDQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbCNMjfc;
       spf=pass (google.com: domain of 34nbcxgukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34NBCXgUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f69WVsTxVbTZpC9j9TnDjGj9PoGXvcdZZAa/G33DVjc=;
        b=odVon12acF2JxfFDWn3wyrk7ixjkJkgGVn+kdYaUEeI5k03pVaQERvMNsz8SjTYOmU
         MY/xiovO+1c9gVdRDeVCU09uSEeMCd47q9ppudpPuMfZ5KPoJ4OMn5bVcp+8+54mQzbT
         wW/jg22Mgma4xB8Y/KWevqJ8FsWW77Dj1jIhH9YdUjaUZfbiR8pNFkq15p+X1HlsMoc0
         T7juTgAkrXudc8Vw680QB+LTjnkunE5gXNbHSagDog3c6LNXS1Lrc1YBw+Pxg0p7kbi4
         ZxaK7sd218EOzguXEaWqMSJbe4ccd6TbTXswgAk86ozxJOQQf/f8MUpKEgI7rZ7PsETO
         kqzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f69WVsTxVbTZpC9j9TnDjGj9PoGXvcdZZAa/G33DVjc=;
        b=SaL8+v4t9ESa8d8e0IhZnXoZfqBhf2zysDmPoAzs86IRA1czkcim3ZdBMspdICYQ3x
         5fMQlChlyVZU4V+GzWQxBj1zCw4KchahpciX6WaeUCMgK06rWqvsRS/rXAn6nnctBYd2
         afsIuMHBqW1iRDGbYLm27VtwZA2FiWQyh+W1NHp1ORpBlWSVc32Q1NEKkapNLTN9b6JL
         92aeRb9dHSP2UMs8PezJDcjfWSFUS29YIO+kzt2XSXDeCRQ8ofBSi9FabPbsrQJPy0Ep
         8C3Xen4mwZ9+xnrn9gypJUKNou44BGJe8vcQGSfXWeaZ0jKAbmkkVCqqAvqjF1gYESFQ
         +ofA==
X-Gm-Message-State: APjAAAXQ35Hg6RkB8lsFXJNEQnet2GyUQfVn3jIu15OQn8PnxAjXixzz
	vRRp9IzcK6CH9ygR6AtdTXc=
X-Google-Smtp-Source: APXvYqwtVc2dXFDerJnYC9k8Efi9XbkNqB8UeoDdwQ7wRKLwBtE3P0wbTXBGRNByuHJeSXHSlgo3UA==
X-Received: by 2002:a05:6402:513:: with SMTP id m19mr6439790edv.387.1581437154067;
        Tue, 11 Feb 2020 08:05:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:8597:: with SMTP id v23ls7196738ejx.6.gmail; Tue, 11
 Feb 2020 08:05:53 -0800 (PST)
X-Received: by 2002:a17:906:5f89:: with SMTP id a9mr6764221eju.267.1581437153282;
        Tue, 11 Feb 2020 08:05:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437153; cv=none;
        d=google.com; s=arc-20160816;
        b=URwpsK01RTHk+CKnH3iJS6TTuqz77E013NabbQx+mK0GVCYO1HNHB+Tyhe8MGdEI0p
         xvxXilk31u/NPoZsx2Xhz0qbnJT6717qn3GodOjXlBqd0RXV8GTUolyPly3RbfPMB7M9
         F3HqGSv/G4YqCDrslZGvGQl3txkhkg2ajcKaG306s4OPia0Gl7SKQGKjU/p6x86va51O
         OpNJuvaf4ixM2MgfqLIOZxo5sCQSwXM5gFj7GYwpE+u5ipgDSE95tY2iDc3l1VOLcemT
         /GSFTR/yroLsCef6VdhxMUgXDY0zEk3AvD0HTD67csIddL1N9x63u75MRAOZiZLse7rc
         JmLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cb6s7Ebfu5RPXhiJNbGZ/32d/mZmA8VpCnoJgMBlnZ8=;
        b=aa/sFXfI9c3ZbN2Uo7RWB2FO+pCdnCx01u8nYjp6TpfdN5HMUaVwbxVKtuoGsgB7lC
         eeraprtvWoDI9P94AJCrT+qYApiD544HEwuVFi4y1eLddQw2IfYRfQ3/K5QbOyuXfEna
         neqAjk47AGO2hpyXv5RI9zFO1wsw7dZIUJIZt+H94GGSsgjoAh+qGRvS2qwT72KJI21L
         UykLABREbRxyqAdGtqQJj7U2jeFS0ei76UUoTy7sZ/mL9Jm0wZqHQVECu5E3WylinUog
         mmYgHYddII9PVSr9eSjlqMIh6HR8yIeaymWdZMFabOPNwkpbKsf0slmlFHv3ZpVGYTwE
         tIMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbCNMjfc;
       spf=pass (google.com: domain of 34nbcxgukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34NBCXgUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ba12si168212edb.3.2020.02.11.08.05.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:05:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 34nbcxgukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y7so29069wmd.4
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:05:53 -0800 (PST)
X-Received: by 2002:adf:ca07:: with SMTP id o7mr8969859wrh.49.1581437152757;
 Tue, 11 Feb 2020 08:05:52 -0800 (PST)
Date: Tue, 11 Feb 2020 17:04:20 +0100
In-Reply-To: <20200211160423.138870-1-elver@google.com>
Message-Id: <20200211160423.138870-2-elver@google.com>
Mime-Version: 1.0
References: <20200211160423.138870-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2 2/5] compiler.h, seqlock.h: Remove unnecessary kcsan.h includes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GbCNMjfc;       spf=pass
 (google.com: domain of 34nbcxgukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34NBCXgUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

No we longer have to include kcsan.h, since the required KCSAN interface
for both compiler.h and seqlock.h are now provided by kcsan-checks.h.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h | 2 --
 include/linux/seqlock.h  | 2 +-
 2 files changed, 1 insertion(+), 3 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index c1bdf37571cb8..f504edebd5d71 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -313,8 +313,6 @@ unsigned long read_word_at_a_time(const void *addr)
 	__u.__val;					\
 })
 
-#include <linux/kcsan.h>
-
 /**
  * data_race - mark an expression as containing intentional data races
  *
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 239701cae3764..8b97204f35a77 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -37,7 +37,7 @@
 #include <linux/preempt.h>
 #include <linux/lockdep.h>
 #include <linux/compiler.h>
-#include <linux/kcsan.h>
+#include <linux/kcsan-checks.h>
 #include <asm/processor.h>
 
 /*
-- 
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211160423.138870-2-elver%40google.com.
