Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWFMYT7AKGQEO4H7XIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 477802D48D7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:24:25 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id u17sf2523460lja.10
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:24:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607538264; cv=pass;
        d=google.com; s=arc-20160816;
        b=dcpEvKeudGn+9ZtSeUrna+Edqf3YayicEjArN4Fu8YDltp36zy2NrTNm0BRMAOlRwu
         2/VoQ+74At8axO2bCt3Q3CW6Tr1NB4YAeMaOUXSuPivrT70GeduwyuGvLX5n5mVYVyak
         74uBitE5qQrgukis8LDNp8ccIdLzhMMkwCPhUqn1qBssqJAKtXoTAJDkvvW136eppXQp
         hanCmr9R8nOw1V2RLY45xXbfV/W1wY/eJ8Qe6ZYCcfELSe3cFf8pzXe87hcPiYOA9zXl
         H9nuf4RwKSBp0inGCFpVWiKJBUA6bobOoRM4dpRq6ILqobK9RqVNFrPWr+nhYADOpV91
         FgKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=tft/hFQI3ctTV06kskON6/2GfDA2g9Vm0fRlE53LuHs=;
        b=M7EJ2Y9KqNpgdmDe9N94oPVR5k+Z2yRuE9Zmwjli5tS5C7Lre6fQJBn0ruWaugJMCD
         O4jlHAAISO6+9peF8xZE8aeBZ1+fQRYg1MNZkdaKnpn39CqSJ6nyslVh1MyOFOIolxnd
         9sIgR9BcnJ/8nnIYGseglnWcI5QGNIORhf2ows8e44sU0XmjK3hQMAQUx5bUnhtcFv3e
         JlL5G5VPGtkuGAHXUy6UKbqcZUfUj+yesc3uKDmzUPlSbcC5lFwmF+u1HoXAfHKYRPay
         PlX1sZ4JUT61PABIYJ+8eikg9lyrFZyg7HQqLkke/WIbpRmRx2UWU3x1JTeTegy2Prr1
         6wnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WwUpx13K;
       spf=pass (google.com: domain of 3vhbrxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VhbRXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tft/hFQI3ctTV06kskON6/2GfDA2g9Vm0fRlE53LuHs=;
        b=Fuy8JHunRpH6GO/ElgpX98/H5aYqY38jVwMf8FZzPXdQw9//aCeV0AG0indfToK1zU
         M4q6K1Qalf4h2Sjo1galo7+CxAokaLBPxVglBd9Ne40yDP/aHHdrk2aVeTbH1Oeho1ec
         wRYycRTggw5R8xvZifzuhSkf+oqJXNY4mgpLY8RvBioDaw3VWkhMl0Eia+jJH42h87rd
         xRkPmpMi+kk2WNqH3kPYoKHJWUYsDnM8KzMWVETBx8u4odeVvoFUIMmd2S2we0RD9n75
         8MBKQHlmzUiniohAqI0Rf85WwIl7ApFMJtAMjVSBPZSyqWdeFjjazr8fvo/gnj3QnuVa
         JNkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tft/hFQI3ctTV06kskON6/2GfDA2g9Vm0fRlE53LuHs=;
        b=Njl6sQs8iupCgGMy+PGAJPqjVPp4P42XqWUUyUM/zdnzDpWWMAdm4vODeyOvGQwQMA
         v4n0Zt67MFe8EiBTUuURRwEMb202Tv1RLNtoMAM0uJaVPNkmvS+f8ZaMWrlVdd7evbsz
         HObx4+h44nbdTFa/poDpCWquc/6R63Tsb5HZNXrIHAFhCae1ph6zu5NnDl2YufQ29qgq
         GUQlW3e2917uwfEi4Qkpr9RYyGWvcWfkWwIP3qJzyEcnVgpsXOSFZgCex0MVTa0DtHkQ
         lB/ZXarLYogOC3fiua+NhWmwGQplfyKSQyqtITpajRugC0m85AaGS76Jm2C1L1aJgtx9
         Vz2A==
X-Gm-Message-State: AOAM530tqmboVv7ik9t3dGY4Q7befJ3P0U8y3+IqhWPFNASRTyabNoHu
	SV+1bYNVcyNmslJavS4CiyI=
X-Google-Smtp-Source: ABdhPJz7DQQ7y0CvBKvpnCqP3hes1PjAc2KJi3yGarhI0Qv9oYnSaQTFJJYNXF/UWzSxW7KJyFq6/w==
X-Received: by 2002:a19:5e5b:: with SMTP id z27mr1371933lfi.143.1607538264782;
        Wed, 09 Dec 2020 10:24:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d4:: with SMTP id k20ls132272lfg.3.gmail; Wed, 09
 Dec 2020 10:24:23 -0800 (PST)
X-Received: by 2002:a19:8c8:: with SMTP id 191mr1332518lfi.492.1607538263707;
        Wed, 09 Dec 2020 10:24:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607538263; cv=none;
        d=google.com; s=arc-20160816;
        b=BfXbehSL0Rq7z8OtN+Gx5o1PYhdezWw15X8SsbPPe4EU3RXdhbAt4albNuMsBDF5mo
         LlayQigLDhhYECo4qhol6KU4oGAwCvo6AfCRBuqtqqpIew1mThPlRtu8lOvrVMMWsx2K
         oQ4u31TGuiA8D6oa8SpKU7WqH1H+L3r9YoLgAGzydEdgNfQ0ZocfCZmXIRGcpd5IctEa
         gfNiJOc5+o8BFv3f9iHeWPpayhcQQXsXqaQCcELPt+dOuf2TMuUeng6dbxvtG8PRT/Ps
         SXSKMCvqyUBmK9wIykFgv/MKAGFajWXWQ+oX2HhMWMB4aEq2xH8fdkuks8/GGFIjSrrc
         QNiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=MhUwCIKPiL199xHdJxg2Ck7LBpRQrLyYixHELfUbAyc=;
        b=aEDcgiQa3sBJLBjkyF0TtAYLf+eNkcIymjLb702Bx0NjodZIdECFh8AbltSSaBVYMh
         0qW/iWLroM8a8SnzRrDKYO+29slMv7jnraWG0ugqjpIMGmQM7sGTXJmirO7Sykoire+V
         xJqxoI1QsxHKMPdHnOfcUKxzVbRA0eIiTkVErLe7ho6jXm5FpDsHnfordon27/Pg88Yr
         KsBaFuEOKd8VB2GZT2EYOxDlJA+hS7hOSKCB0xKye1ElNkIq/YqireRifeBdwkleNAsB
         hOmZdk1XIonTn5Hes6JlxeQ4AbqhS0SzWXl7EWX0OrlsZpES4dhfcS3v4jGdyN2PVKUN
         VO1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WwUpx13K;
       spf=pass (google.com: domain of 3vhbrxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VhbRXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v191si103920lfa.9.2020.12.09.10.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:24:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vhbrxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v1so960670wri.16
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:24:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2e16:: with SMTP id
 u22mr4177436wmu.149.1607538262970; Wed, 09 Dec 2020 10:24:22 -0800 (PST)
Date: Wed,  9 Dec 2020 19:24:14 +0100
Message-Id: <cover.1607537948.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.576.ga3fc446d84-goog
Subject: [PATCH mm 0/2] kasan: a few HW_TAGS fixes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WwUpx13K;       spf=pass
 (google.com: domain of 3vhbrxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VhbRXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hi Andrew,

Could you please squash the first one into
"kasan: add and integrate kasan boot parameters".

And instead of applying the second one, it's better to just drop
"kasan, arm64: don't allow SW_TAGS with ARM64_MTE".

Thanks!

Andrey Konovalov (2):
  kasan: don't use read-only static keys
  Revert "kasan, arm64: don't allow SW_TAGS with ARM64_MTE"

 arch/arm64/Kconfig | 2 +-
 mm/kasan/hw_tags.c | 4 ++--
 2 files changed, 3 insertions(+), 3 deletions(-)

-- 
2.29.2.576.ga3fc446d84-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1607537948.git.andreyknvl%40google.com.
