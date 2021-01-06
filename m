Return-Path: <kasan-dev+bncBCJZRXGY5YJBBAXJ277QKGQE7J7VGBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F1FF2EC24A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 18:33:55 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id q7sf3254898qki.16
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 09:33:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609954434; cv=pass;
        d=google.com; s=arc-20160816;
        b=PKZa9kBf59epIf8Nwx7QMqnTIShNw6rrR584cPf2dGAuWC+uqD2m6UH7Q86v75LmX8
         S/PnhnmMZ4GhSs1RviYRJD4hAUqsX0mXiZYrjf743fhiz3apBQi3/l/NsDzlAWqGqrkT
         5UCyZ5JIJ0Zeo17YAS2WKS32f7Uhs1HA6pV6GZBxXQTC/ljQCfCjCIp3aLVgk3sSqyxx
         G3vpSpVO5SJeDu90bOR/CFCLOySI+LhOzUKrgdohTzQi179YIN3xXE1Yhw+f+zPo+USv
         abmUsDiQvVxwHXvVZ1s32dSu8pmhvUMZ5Y/9kFPxAh7A6YPBpAFeGpezdjdcEN5mOKMs
         lRnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=RCi43qv4SlMkCXCm8nVF+DT/jzK+pDpy1Odnc6/hnIA=;
        b=xaFUHBC8JHQA8K5aspKv+1yX3ECY4zc9ubV1Kj68ZdB62VfYkDp6E853sMi/ZqJvnS
         +UIVuMFKGsIuQur8SAVlk523OnLR1aZJUyd3agvm0tPXt1pzuRV3u+R/ZqWVMuoO2j+D
         hhBpW5QQE25EffDmNLU9wSNYwwnEbyIjUfo4Qm2vrE9fCHXsOnUfVPDYwuX/RUMKkfAV
         BF3UM0fYZ4vd8PxOW16qjfeeX57r3YM2x6HnYFU60KsbNlWWogI3tqdMPbpl9UqHfVHR
         gTjURsLecRHqpnx/XqRhi1eK6ylNZVDLmdOcn7fp8zpqthBjiYMtgsC7nolwbvvhHAUy
         hFFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NnawW+P9;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RCi43qv4SlMkCXCm8nVF+DT/jzK+pDpy1Odnc6/hnIA=;
        b=mgbleR5kcfk+i18DczDzl9rE06PRRfKfez4zihniOfsMbfBnsGHWoX1ErO9NHPcIHN
         I8PZ7XzUu9UfkQe/BlgyYB8s8qjmQqR7vckzVlH7PC1qg0nZJQL/4DTFdxi35KhIFqTU
         pBkZ78/wUpWKYvZQq02p7jhdaqFfiZxtYVBr8rEeXVQyiZb3j5Ar4nhZQWXgWjmODlwb
         pY814IcqKKGhrbDHnBs50wLNPxd/GUNnlL2OP4WQ8dtU5RwjrDqHuY8AtuzREhj4tMIW
         1/vcR4ptYx3sCgVHCaqgZ39jMidqyB9nCc1Q01i8ivw/oE5+HSwy8cBgV34SFW6ei52D
         6Zaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RCi43qv4SlMkCXCm8nVF+DT/jzK+pDpy1Odnc6/hnIA=;
        b=pxzI74qICL3nbHl1lh/jP/TdXhd2EbCeLJ2MKsQWdAgXV2htG89GjLWKpGbnYQwtzU
         q/pUC1dVQn8x7YJYEZWA+ixjhtrcOdwW7SB8evW7MfXazOwSPReMkWOwldz/7ffcmABJ
         J7OymRu5XMy5UIVk1Lj4UcBdbFaYyXcNUHoB9aRCgb6GaE+XG1o+qKHVpPbzwqULIMZx
         ItwftgoQ7WZQPOonISWtFXqXyXkcahqxyGjUlh3DdZ3hpyNsKTsr3QeVDnZTClznx4F2
         CmVv7JsRDU9VT+c90CQrKc+KdJHReZihm+6KOZiACJKuU2P81i4UYpQ84yQWNCt9FoqZ
         7ByA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SEpeph6Xzdn0hS11CaMmjG1KEsPSdvUh18705pRJzR44dfUqb
	5ijWTe4kF6PfSxqz2+CAeNw=
X-Google-Smtp-Source: ABdhPJzxrFxgg3/8kbOsnLIsP/4Htshhn5KMg+VOD5OtFM3U60LUaObCkufIQbOexlbueJo1WytyMg==
X-Received: by 2002:ac8:5794:: with SMTP id v20mr4898403qta.175.1609954434254;
        Wed, 06 Jan 2021 09:33:54 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:242:: with SMTP id q2ls2119583qkn.9.gmail; Wed, 06
 Jan 2021 09:33:53 -0800 (PST)
X-Received: by 2002:a37:a241:: with SMTP id l62mr5203869qke.482.1609954433753;
        Wed, 06 Jan 2021 09:33:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609954433; cv=none;
        d=google.com; s=arc-20160816;
        b=NNVoMu2xSzMmy1EoliX/klAKIZgh+UyfpI2CwRr3u58r+AZagfcQrzr/HImlSf1XOV
         rU/BlNcjgfGD8pf1u1skkQ+dc3SJUBlAXSSIx+W9i4EbYEnFJnX5y/6uU40YDDKKrq9Y
         iBKq6ZrMnDIFeOFZm5jGiHXkbUdvyzdKR0BdUP+35en7xnK/W4G7qxMVBKKVpIapfbf8
         3Hx+Rn66YZmkP+6m3LwWNOIgmDVbUcdqzSwtTM5j8UxgWMPVQO/d2JXpRfG8MB8f1m2M
         3EXZQa5SMBEqiWTADwkSf5DeZUF2SBabhgELqRnYY89kTB37RPw9qszCkM91hv8bRvd5
         Sa4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=8mnSY741I5Lu7OaRQlISUV2Mq3Eyk1uUYBmQDUOOli0=;
        b=H/dtpXLjcRl/cqkwv9Q8VRzvlELpGuMkATKOxPKye/alG3yALlenkNEsQxLKEr+bz2
         4CUKjrTc3+jVwJdXWyE0X7KsFE3EO8k/hF5BEkxWFdjwfHuAWH4yuv8EFObAchmBsAHS
         dMFh6nMCjzjhOY7HDJ16e8VUwgkG0ka6I1soLBk4wIxG/eSzLV+emnkk2i4Wg1w7vjTb
         aI40sW+W1LOUY19mWuG+OGiMrgq0dsHg6/7nFZje71zircie/0wPszxhO4m54Yx+ais0
         RF2SL+CFXQkpf2BKigKfcMWI7ioD7Rp/hJWI0udDQEM1TIHyPo/ojAx51Xumm42hPMaY
         ag2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NnawW+P9;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t2si294924qkg.0.2021.01.06.09.33.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Jan 2021 09:33:53 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 914F02312F;
	Wed,  6 Jan 2021 17:33:52 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 2/2] random32: Re-enable KCSAN instrumentation
Date: Wed,  6 Jan 2021 09:33:51 -0800
Message-Id: <20210106173351.23377-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210106173323.GA23292@paulmck-ThinkPad-P72>
References: <20210106173323.GA23292@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NnawW+P9;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
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

From: Marco Elver <elver@google.com>

Re-enable KCSAN instrumentation, now that KCSAN no longer relies on code
in lib/random32.c.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Makefile | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index afeff05..dc09208 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -27,9 +27,6 @@ KASAN_SANITIZE_string.o := n
 CFLAGS_string.o += -fno-stack-protector
 endif
 
-# Used by KCSAN while enabled, avoid recursion.
-KCSAN_SANITIZE_random32.o := n
-
 lib-y := ctype.o string.o vsprintf.o cmdline.o \
 	 rbtree.o radix-tree.o timerqueue.o xarray.o \
 	 idr.o extable.o sha1.o irq_regs.o argv_split.o \
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106173351.23377-2-paulmck%40kernel.org.
