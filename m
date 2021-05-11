Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0328037B273
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id f12-20020a056e0204ccb02901613aa15edfsf18023724ils.5
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=wbu6E9v8qv4F11H4fHwVRZ8AbFT6Nur8FrnKaKhR/3levPC1onOdKxa5haWWJv6kyZ
         S4GUPLnyfCPm9CFVxUkIo9m5CRPRqCvvUVJKkPbmqfw5jQHMZ6u72WPDSXiY0/YJNLZG
         C/I214Wp+cB8lvoXk/V2CBG69HKUkBV8RbXxJQIeBfHQhpm9NXMJCxU/KMBH3Ni1shPC
         MCc++stxNCfhq1XKpFn02WzZH3vSjUyGStCHZ1F05VjKLtleguHDvF6dQuOTi0Qrks2O
         JYg5t3ayb5rFIcRyglume78/kLoYxPMVUS6QKNHJ4wOHoFKS4rrPxcyQIIXolvIpdcwd
         UKbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4wR8E0hKbgQ0tJ0F+KbzfwgJrAyVrrSKzSYypNk88ww=;
        b=qDnn8I0PYNnbAbCdC/bqDoQTBGcXhFaYYJcLgeaUpumxYdPeokb5aewXZOp2jf7hnP
         ji+u99MhUPgJGfoaHu/PkXNFz2F8E3qnb9vDvEPS3uGNizu4OlME+xtMF38OCpXAm6Ci
         CxPEs5A/crFWlbZdrMhztU4Qphk80ManIKy/A/nUMjK/lvUVkoX15LEcMguRGIT0uDNP
         rwgQBIzUV2r/jlyIzDUmsvIJIEfUGPnMCQCOmK1tdNzLFpQIVLCc6fttk+7LUAHRpM/R
         g/2RoU2Spuud+3FQCSBeE+W50lRNArTEtddxGU7VNaor5I7iUK4NXY14gRFLU+gGFf3m
         EIpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cekeiQ73;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4wR8E0hKbgQ0tJ0F+KbzfwgJrAyVrrSKzSYypNk88ww=;
        b=IJp4aVw8YpD93vebC/TiZrNhS2PFmIR4l9Jib7J1wpwzMTqRdDudZrPjIQzWFe6DM5
         CKOiQVbwV8HDEQqpGWBCXEI/MKpClBjx+gAPISF/QZPm6DnaY62hg/SZBDgQiBcHc6sh
         YoCBoS/cdV2vbNkFXAXR3hoZSGxaoxUlx7Fl60Kg+3V70ZjjjEBkzG5UwYk7g8/72yyo
         wsoDJzmgi/M0kdSKkM10fCUoM37w90P+6yrwHUG4W0B+7mGkSW7pOEixtAwW26En8yRU
         LpvPkNwIMs4gDJwcEsQOrpr9J4JRJNHMOwS/CNP0Wg+kN8cjKkAcFJl/4tdAlXnO95dl
         JJXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4wR8E0hKbgQ0tJ0F+KbzfwgJrAyVrrSKzSYypNk88ww=;
        b=kAFyJdxVIM8XA6rsxfi9UJMGo3raK0Luk/oaynPN3vMcphaA9KsnzLXSjJc/kJFrgf
         3AHhPxvpEd9gHxsczFla+lQNCJkYeTFDr4P74wp8Xj0mz3sI93b8NNoauzRXgp753H+i
         5WH+2PItoEiEyb+UoqgQOitzMQglcW1mPQ16B8rAvW2VXGIdbmwRu3E6ZDbNi014DrAu
         RzmAOB2jou8WUULHUK2bP+ge1BalKA5olBwAxfY6674pgy4hR2UFDslcA995+FTaxYrH
         lXOp/c3y3F8e0uZOZ3rN1VNyr08g8p7M1HSw6Wd91+X/i/RB1oOruHHnRLPUW0tKvnQA
         o9+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UiNBN9whdIoA0InDSGAd+xm6DNfG9PitbiHf/aSOPTGrI2HkQ
	5+BsqgncyoqscBUg07lTx+c=
X-Google-Smtp-Source: ABdhPJy5oMx8UP2HM7ncO1BJJ3741OeyyM9pEG24Sdhhn2wVGWuZs75T0NDM9C61U7XLcPXMOeSACA==
X-Received: by 2002:a92:280b:: with SMTP id l11mr28225892ilf.111.1620775448069;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2cd1:: with SMTP id j17ls50100iow.8.gmail; Tue, 11
 May 2021 16:24:07 -0700 (PDT)
X-Received: by 2002:a5d:9ada:: with SMTP id x26mr23715635ion.209.1620775447773;
        Tue, 11 May 2021 16:24:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775447; cv=none;
        d=google.com; s=arc-20160816;
        b=T/8P3TDUnj1YqFYdY3gVOq+qCHrSaJWs0x+14WHm3DMaNEZAF+wxUTGN2kDMe7fP+b
         WStgdOJ/8vv4UuDFO0hUQoL/YU8jUdBBAszaHWEogwNS87eVOs4CW6qudfXEc/tO+U1W
         7jAxF334ZsWZ/8tnGxvPSUCize94t/Vm7l7313fhRI6cq510m4muM0OQGsKKFIus0qb7
         Mu9M2AvSyzStCdI2ay5ks3o4udz6b1rKglonk3pzwVjMXHrmjFl8y/1CiYVZWtbMtLJo
         6kRmvraIHulpkYzPun5qHyMTyL+OSmW0/P/AGbnsIh/8/T3kUF+iOoWPHhuB1mL6KJJf
         6l4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A20i0SoIuLpcXbJ8LZcxNTJyjuHePkWA1xmbflWD2nc=;
        b=UmJvcySzbIyR/8vG4QMK/HEYVWEhhYJb5XJ1ktk3eQbJ0ClcD0o+XSGc9BMUCogZX9
         nVVzmPuX18RPHQuC8Ybs/X2PHz/dDaSLFaMI72FtE43URGiL/wy14F2nuIS3z7GrYKsx
         X30VekBvyZXOPXNYFseg84bwSCDJ73vXYa2mPchM72VPFLvq1D2CGo86mAcD0KdlYj8B
         mYJsreZ8wJ+dtunYsSKl17/Lnt+v8ROPfVx8l1kLhGj9XSdnpp8KkNfyQdC4SmlanJWX
         1eQAubg34lYRwT+743Ktn8i57XWcSbNqbmHO+QZgJf1iTVRrV0HV0CxKIxkUCMyTInAn
         2Chw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cekeiQ73;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l25si1347041ioh.2.2021.05.11.16.24.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E4D5961626;
	Tue, 11 May 2021 23:24:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 99CD95C0138; Tue, 11 May 2021 16:24:06 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	"Paul E. McKenney" <paulmck@kernel.org>,
	Akira Yokosawa <akiyks@gmail.com>
Subject: [PATCH tip/core/rcu 01/10] kcsan: Add pointer to access-marking.txt to data_race() bullet
Date: Tue, 11 May 2021 16:23:52 -0700
Message-Id: <20210511232401.2896217-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cekeiQ73;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

This commit references tools/memory-model/Documentation/access-marking.txt
in the bullet introducing data_race().  The access-marking.txt file
gives advice on when data_race() should and should not be used.

Suggested-by: Akira Yokosawa <akiyks@gmail.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index d85ce238ace7..80894664a44c 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -106,7 +106,9 @@ the below options are available:
 
 * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
   any data races due to accesses in ``expr`` should be ignored and resulting
-  behaviour when encountering a data race is deemed safe.
+  behaviour when encountering a data race is deemed safe.  Please see
+  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
+  tree for more information.
 
 * Disabling data race detection for entire functions can be accomplished by
   using the function attribute ``__no_kcsan``::
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-1-paulmck%40kernel.org.
