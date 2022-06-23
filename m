Return-Path: <kasan-dev+bncBDAZZCVNSYPBBLH72KKQMGQEXD6GEEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C375588E5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 21:31:57 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id m17-20020a170902d19100b0016a0e65a433sf50742plb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 12:31:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656012716; cv=pass;
        d=google.com; s=arc-20160816;
        b=V04CdiFVcdeTpM64+TU2rbfzXh6ofYkck87Dqgrzr3xp7qrWPYc3sf/psEbGMb4Pvi
         Tds6BL2l6V1yoHE69xnXyUTJPIIORBBH50EsiHL7EdvHvVkFoFEoEVGrUa82ptrEouY+
         nQk21V1T2PCdQaSpX76OqxtyNdXuY4ynwTbYPXj2acwpesHmpeMxDUYsTwJyLdQ+j+Ot
         M4UrTMbgDxncLQm2oYo7ewy34uE7+Fl/MNQJ+TZi+J2R/x469ziU4+EGwn5VUnNPA1Q5
         tAQRTGAPlRjHBdUMItP9BJDgcSgJ3X0Sb7wYhej/L0Ec7AwOv560Ec4Hy7J4SfhVfbjL
         Lm8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Y8vHlxHTbiQSGx2iJ1r2FCVNW5vg5XR8zIlDEjhWm6U=;
        b=hjEJGzKwxw+j9QE+OjFzbElskLJf+BSWC2PKlCRk48X1lVmzipLVFDI90BK9ElmnRM
         QTbk+4MLSGCXEMJtIWUk0jFDw/kW+GkOYh70pydcTo5lyY4iCWJFszGtPSP3mrwANopj
         EpnJqFbW0p2mp//FIeoYDJAJNt1ODMJCbUfx70TxRfLlQHonoeKS9G0rYjB+LkKccM0d
         o9pmGRSJBWe48sswv1+N5g5A6VfksAajLnPc4AaNbkwzBFlHY6bqkB14cjBFm+eLuN7g
         kDZde8zHUUbPstqVq+GllLsv5c1wTOOfutJk5arJr4b6hU/2x9MJSLGWZp12xzlJRhFM
         vp2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nFPwT5Tj;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y8vHlxHTbiQSGx2iJ1r2FCVNW5vg5XR8zIlDEjhWm6U=;
        b=IIxrqAtdKRSxfGm4fL9zc++1+T8r2u4rUmSh2mEjnUelAh7hnHJecppvHs+sEVo77p
         7Sca8nIUV9sWFI11PkhJlLJzkRq7Pe4Um4UGKZaax3eG7b7Ef0gPpPwxJQftWUWIL0bj
         xADFv9EsWtv61fQ62qLKi/a0Bt+y9G9rYw43Rz0ohCLidfTyxYg01u7LP0evAulXAKzN
         8G+86+DvH323IHL48TGmDIAt4N54u1viQA4Cnj4E2PLbI1tWGemg7YWaJ1KwgDNah5u4
         lNONCNm0F9iUvLOGM7GIk+5yS+xDlDsjJb0MpFi0C/OJjzsQAqLRJHVDoStfrsYPveMd
         1+Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y8vHlxHTbiQSGx2iJ1r2FCVNW5vg5XR8zIlDEjhWm6U=;
        b=VJlgVRMmPz/bto4OwCnfpvzNHwE+1hRWtMKIzl0X2y5Mfs/tuXE3bw6KRv21gzjX+1
         Y0uGkc8DDBMGH2kOR0nw5VDlmWlbcbEQCR8LnxdFgIORrOEEe8s2VncBdhqsF87vrDVg
         6Qd1cFuDJ1a6bRK3qqKpVyHpA2fiV41QksqL2SIdHQ1V33dx7SYHRyLsS4z90Ny214t7
         W0YirMRZr8Cv02QPc8iM/AEkyPcOVrhMtQB6v2ZkAUQEx6R3E1mc8MUT5bMWIJW/AQQe
         oMZlQs7GSWXQv6pGpoGAvBXXNCCDPmU2V2LMnmPSba3gAQiQAi2LoedoTiKkF/AZQOcA
         VItA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+pT/6UkgbbhkpebXSS4QS60reWIa25EL4ln3uTDdMTnXcb3Ggd
	XcKvPLJyXwT8crtAtb7oP5M=
X-Google-Smtp-Source: AGRyM1uEWXyB27x7KIp5pPf5kFyar0PDkUULdsGky08S9vzFS0cCMDK0UwxXMG5j2SQBFjOyi84xUQ==
X-Received: by 2002:a63:145e:0:b0:405:70e2:1d04 with SMTP id 30-20020a63145e000000b0040570e21d04mr8552978pgu.487.1656012716151;
        Thu, 23 Jun 2022 12:31:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5ce:b0:16a:5424:6ece with SMTP id
 u14-20020a170902e5ce00b0016a54246ecels2327460plf.2.gmail; Thu, 23 Jun 2022
 12:31:55 -0700 (PDT)
X-Received: by 2002:a17:902:ea95:b0:16a:3084:2925 with SMTP id x21-20020a170902ea9500b0016a30842925mr18277912plb.166.1656012715472;
        Thu, 23 Jun 2022 12:31:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656012715; cv=none;
        d=google.com; s=arc-20160816;
        b=PaDIsBSPvWIDDZYADU1ZymfbtqynaPtbDe8fCcQbltL+9ir08gKpqXJPtbRDQ4pZjb
         7NwIQx5wtZ0x+0Sb1C6Fa/0Zz6Fn5sfrl6upz+sVCSGvhAuW2Um1TaQUlG9zcm8nmzlY
         1K/GXhx9YDlBtvsWxO3FCGlRPAWtd+urhVAtP4VxAoMeBr0mKoCgnyBwThkU/HUpwBL+
         LuDLeI3tcmk/BqYImlImJg978qWsx3MB8ih0/bFAuv341nxM7U85dU6lHdI29fHDGNvD
         XV0IjvMbYACgiXiljIwh+EE4qggcZBLxNSuPb5F3hMwujdbLhxJBV8mmvhzB58QOPt2u
         Y7mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LFoS0gTejyApL8XAEuzc6iBKEwtkeedtvIkXJUakIOI=;
        b=N4uqSHF9tobxTZeM37VNvDb6JiL35/T74nmnxIA9CsOU3DIr0Ros2yXTQ8OJ8i3ndv
         yAOzAyfwTeDQtk6/TxMsAoeXJeNaBvmNXgm64ILAAooagZnR1XOi1Zgv1vBZ6RfdEklM
         Ile94vh3Lob+1V36+J3F5QEJrd97H3knBcWDJ4PxsfJ7ZIkAageOO/q7t5+jkST4sqN5
         rUqaIoEvdGdRwfOsWexiCCsDFUv2ZujCHW+2UfchcgYa9dAGahkf3pxsFjIS8tyUkUQw
         MMM6nIgc/dR1YoMZ5rkIyKn7VgbgdZfpvKn95phTEiY8jrbBblWtCGZzfni94waiuEI1
         +9ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nFPwT5Tj;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pc7-20020a17090b3b8700b001e8520a65e7si13756pjb.1.2022.06.23.12.31.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jun 2022 12:31:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id ECC40615C0;
	Thu, 23 Jun 2022 19:31:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 85E6FC341C7;
	Thu, 23 Jun 2022 19:31:51 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: andrey.konovalov@linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/2] arm64: kasan: do not instrument stacktrace.c
Date: Thu, 23 Jun 2022 20:31:32 +0100
Message-Id: <165599625020.2988777.9370908523559678089.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
References: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nFPwT5Tj;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, 23 May 2022 16:51:51 +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.
> 
> This speeds up Generic KASAN by 5-20%.
> 
> As a side-effect, KASAN is now unable to detect bugs in the stack trace
> collection code. This is taken as an acceptable downside.
> 
> [...]

Applied to arm64 (for-next/stacktrace), thanks! I had to fix conflicts
in both of the patches, so please can you take a quick look at the result?

[1/2] arm64: kasan: do not instrument stacktrace.c
      https://git.kernel.org/arm64/c/802b91118d11
[2/2] arm64: stacktrace: use non-atomic __set_bit
      https://git.kernel.org/arm64/c/446297b28a21

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/165599625020.2988777.9370908523559678089.b4-ty%40kernel.org.
