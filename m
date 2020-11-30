Return-Path: <kasan-dev+bncBDAZZCVNSYPBBZG7ST7AKGQE4MWE4LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E53FF2C8B96
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 18:46:13 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id u8sf7370875otg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 09:46:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606758373; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTaor8tQN8uYS8oyK5HHdDLU2r8wbeLlcQUyIg94f3JXFm0+8y21CExOyfb0jM3QpV
         nHGPlmZAQFG0GLgklVy/RI4v1Rt28dR0pMlY2zzwJZGo+u+F37v3Qzm3njBYOXAeCCDo
         l3aKHM7KkYBSa7498tRQSu2N+BSUOH/Xj95H/KVoBFDBCKxnnq4bCaRZqt7tGzoNUeKR
         FIiJEipdJzvXWDT+rPfr15ba/xJr2kSEsKq316yNENW3Hab6w70hW1eZ5wdU5PKT1eEl
         BjgFD/PyFCG2iQcpUrTm26PsV01px+LzfAEMiGdpNsbNP6haNr6YJUy2ycc2YQE3D/RN
         gKwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KQgtv68JPjIjU5iVdNW+KDHtk33rBA9XVws9fYIYQKo=;
        b=LfXlcOkvKHJj5PM33v5VBsnydqkIqgE3SMMnoQ9K/SiSQfNHmb4Jz2ySHZ9QUT3CXb
         inCMhpxc3t6QGbCfnputyp9M0+CinKTn7rDP0LhomECFcvYhINAMsnyAd8XBMWQ6I/gC
         QFKRLE7tQp8oc02ETyT2M3ZdD6bbH94OZvy7yL6UIwZUDnp837CaKA417n0yxsGekkWw
         jg6/J2hkRcQzVLDbj7ED+cprmg86UrKmXEo1NyrIv9cJn6Z2uBf68ZUbxEHkqEWTSnDv
         nLqzmAHWLTczzc81j9ipQM3yQcyxMeNDWdSZuXJ/GCIA4irHPq58VZBCueXBHzSn3kqQ
         KhNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hL2uDGfg;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQgtv68JPjIjU5iVdNW+KDHtk33rBA9XVws9fYIYQKo=;
        b=bkXhihVe+BhEOarmw8+Pf0B2FaJPLRG5eHzARvCMq0PIL79uI6MQioDvVB7fOVSNdu
         VWWqQhkT8SYmYett40i+o7kiaRmC3XIDd3fzikuJKq6Mg5p1t5mtTQx2I59GOV95jWkg
         KJWbrOqJv8zYY5A27qFlFRKxvOt+mYTA684K4w3n47KrRlWTo+nLao7Rsp3bAY4/mpTV
         uFSziFpagc7ZBBhfOsTO88QknCbzYE+5wXTN4QdHVnMiQ5eFRgyDnnX4qD/5yZqyhb8A
         aAHpk7AZAifdcc+ybHsNI2gBV3vTNAoQtkHUZeB06tKgogKMb6mMtIWBIe+i3Ek2UO8Q
         GeJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQgtv68JPjIjU5iVdNW+KDHtk33rBA9XVws9fYIYQKo=;
        b=Y09ZrVN0K6NkTVAea3pRksdVGBE+RZTdluqH44OuLfpoF1HUgvAWB63Dqu60HPjlXV
         WSe9NCixbkglF+6MWrfVSNouTyCg3atKqAIUgQhkZqQf9GXtV02PSrha0iVDX4p2LixA
         Q5Aq/PJG1/fiQ1NCDbNZTOK0WNaeZfc+Vk2tjiJe5nnP4FJYVe+ja+dDTgx5ZUssElMG
         9t3/xDYB47OWW9oegHzAyfV2KlWvBtwIQyezsAPLihDrnmJyds9vTFK54FSis2ehl/4N
         /kIhk7yE4NEa15liyDXC6e4BDxcDAml7LZFepHT7VJ3HCEuNmYykhR4fysKCcjtgA3y0
         goJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Z0OFsSlmE9T+GtWZFAfD43nn0Yt0+2idQGQ82HVmXWLPModSu
	PhTxlQLWcIeuR6vUzWYxu5A=
X-Google-Smtp-Source: ABdhPJwEQ2mE4N1tZY6CKuCMKxjyL24YqMuRqAn7v4DpQ3/83Hrlqv3h2YK9MINA+TwLSdR9rdoyZQ==
X-Received: by 2002:aca:314d:: with SMTP id x74mr15417918oix.46.1606758372788;
        Mon, 30 Nov 2020 09:46:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3558:: with SMTP id w24ls772189oog.5.gmail; Mon, 30 Nov
 2020 09:46:12 -0800 (PST)
X-Received: by 2002:a4a:dc1:: with SMTP id 184mr16412978oob.40.1606758372423;
        Mon, 30 Nov 2020 09:46:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606758372; cv=none;
        d=google.com; s=arc-20160816;
        b=CkV8N9EBMUHJzDYSM4mSe7k0oTubOGaaPgSY14IwJD6zRy7Vcqu9Bq1CFFVh//5K3h
         YgtOCXX7X1aXtVMWg3mJpTO+0h+QQWr8QcAw8ZEg6mFVQ4zf/sq9rKfYRH2wJ1OpRX0q
         UZhXe5+nD+jHfFkusBKikvFvxHH5ceLf9shfZTyMqXzuxuPC/NsuAfSWGP+rxKIqxqqu
         ym8QX0rRJwiSYp3CXDjcLtlkC2bnBV8exD+glCLPDJNF7VzFCSeMgpPH71ygAv5im7on
         ie95n1vysJdYmeQJUICIhgmrQ9Mib6+syZo1oKRwgSfslCofM3Rkbtt4GyLqWihXtxgx
         CU6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1yM2OB/XGDvQnaKjenoNfPx1c1Eti9lvP0D7z0AEAfo=;
        b=ASwJY1wjqVP5yp7ms7sEL0eOo715FBM3HO/deZNZWsyI0hgUuTETCAFCMTu1yWpgvP
         CMR4eiwNVArAGj1JcdRd7PLiJPn/S38RKWJLgHMzebIB97/nZbkirDI+d7WD4isaZTVT
         ODAZVX8n/z3uuAynRrnL9GIXnc8l7Ay6B9qJ1xprrRQHn2WpWAs8ppeawh2R3YxyHzh2
         GmS+nbgWzrv9+Bk2IZ34cJKqgfRthfVUqP2kPd6zibnGPtH5oXHMBwtI0VWRYiu3QWJg
         0x0ENV+7adEJZyLR7cmPhayT9w+FEdLlO+cniDfjj5CNtkGcbBM52ZnlegBemQyPuw20
         SEcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hL2uDGfg;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l23si1226060oil.2.2020.11.30.09.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Nov 2020 09:46:12 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 170D7206E3;
	Mon, 30 Nov 2020 17:46:09 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: catalin.marinas@arm.com,
	kernel-team@android.com,
	Will Deacon <will@kernel.org>
Subject: Re: [PATCH v2] arm64: mte: Fix typo in macro definition
Date: Mon, 30 Nov 2020 17:46:05 +0000
Message-Id: <160675781246.1059114.15264398791864566541.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20201130170709.22309-1-vincenzo.frascino@arm.com>
References: <20201130170709.22309-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hL2uDGfg;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, 30 Nov 2020 17:07:09 +0000, Vincenzo Frascino wrote:
> UL in the definition of SYS_TFSR_EL1_TF1 was misspelled causing
> compilation issues when trying to implement in kernel MTE async
> mode.
> 
> Fix the macro correcting the typo.
> 
> Note: MTE async mode will be introduced with a future series.

Applied to arm64 (for-next/fixes), thanks!

[1/1] arm64: mte: Fix typo in macro definition
      https://git.kernel.org/arm64/c/9e5344e0ffc3

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/160675781246.1059114.15264398791864566541.b4-ty%40kernel.org.
