Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLNP5T6AKGQETCWBLBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id BC45629F515
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:42 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id v145sf1559805oie.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999661; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6dALO2kDCOJxiFSSMZDIxLLo1RUPeNX0VBqRFcio6mtYRQDiHowVI+dgiOf6nvHbw
         2uHsKupJlmSWdSPT7D8jn1wnkpJDgZRJwFg+PnIo+GzEs46mSopsMP1UHt2r7qld0+L5
         NLs8PBzgCpUQH1b6OdvUbLFwNxFbWW/2SmYtPg6krgUAEjANz7mQrxLUCZAG4VD6w5eN
         Z4pBH7NTUlSyLeEVhczaB74JZe1X+O1CrcelgR7Kov5LZIZqwVenyC4NjwqClLKFVWbc
         AVrijLZFSTSR/X2/1V4jgazXNqzM58ksq05G7j8szRwSZhp4XuoAm+ZsR1g/+wr5vczj
         bF3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+VB9aguZLPwOuB8dq+jl/BRGxlG+PKSfA+HZJPMto/M=;
        b=JunMXyPts4Ej4B/cq2QrxxI8ESjpuPmXRbeQrrkRVtkHBiMCjUOBH0xEB9PL1YAZz3
         pa3onE8IUJN6magjEib8IooEb4Wa5VYWaV2cOrpFQ0uJpgiVT5CLkExE46ac7Ld/Sug4
         N7ba0nGyzercP5quGtINwMosnqV2ZWljw69lRzFQVOGwiWSfTHHJQ+2ENydrymskHZDz
         SCLOHQ5LUqnlHyig4udQqmH85LHePkxtHpfuNit3InQUrOliuwlVUDLpAYp58BBJllbS
         KRNQ7rGztTe6iQp57sSfb5YYVJxJenuiWByFoWPIA0rpLiAjr+RWmEcgbOX6+etI69tQ
         1Kmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iz5mJR5P;
       spf=pass (google.com: domain of 3rbebxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rBebXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+VB9aguZLPwOuB8dq+jl/BRGxlG+PKSfA+HZJPMto/M=;
        b=sCup7sdmL2Wz5X7JovVko1DqYk8nkhFxLxZ2Dgij7NjqibsiMhOILUNq2U6e1aL/U4
         2+B8TfghrXERl8NUrlCQti88v81WdCdeeQAJJlvpvuL+ebKGy7ubH2sLXqejWkxe9UdA
         UGCKthDIq6KKskLTo3r/xIWsP+gdW+7N/jD4h6BSi8YCMluJYaCWhHr3FmT+p5NIjwcN
         wUbE8PRBA585ndNFM+BY/PUb+O6O265+1cu6l2ja64x6LH2kFc2zwoT5qiS/P8Ihq5He
         F4pVZ+eX8cDCr0sJaayaRHoZn9rkuI+CqjpK6eOvpu37Z1hFwM1LcJ0bOKh60OQerA1q
         jPiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+VB9aguZLPwOuB8dq+jl/BRGxlG+PKSfA+HZJPMto/M=;
        b=MNUwV5APE3hEzUS97qOH9DBAkfcoyE6IPryRBHbZthuub9jHXiKHZeFKXrKhvH/e1E
         RfrRJrADQx51T4yg6wtAsr7Izb6kFgnOMx2An3A8oZpLm1/zm6tw7paA3z+4XSqOT8+a
         u3E5DBmBZEC9x1nkSZqsqYVaD2O5LXOw38VmuLAiIIx+LlZ3yDC3SWaGJx356U56QGDm
         PNUlyWx0Pyf1aerxYIj6Yciv3Phii2Cr40cTNi0yiEd4bpm12KZVjCEk/yqm6cDb/mpH
         EgN9mwcoC8YYWJQA+48IkB6s0qOl4nKdJJUqbiHinm+6Gx1PQ5BFOwYZRK/bihKnHhc8
         sYGw==
X-Gm-Message-State: AOAM533Rz51JxsIxcm6VViL4Tnfer2YIh2uOk9BO4niH7IhCiTVKPFT5
	2Y4mkumRJmHy9GD+ELXmFcI=
X-Google-Smtp-Source: ABdhPJy9bJoNPQVtsVL282pZvEeivnlNVVlbDXPGVAV1AjDSYvLqcezAtU9Le53irG8DB1UYuuGdrw==
X-Received: by 2002:aca:d447:: with SMTP id l68mr563928oig.168.1603999661681;
        Thu, 29 Oct 2020 12:27:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d650:: with SMTP id n77ls941420oig.5.gmail; Thu, 29 Oct
 2020 12:27:41 -0700 (PDT)
X-Received: by 2002:aca:49c6:: with SMTP id w189mr928645oia.58.1603999661363;
        Thu, 29 Oct 2020 12:27:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999661; cv=none;
        d=google.com; s=arc-20160816;
        b=ZINyROemalqwkg7lQEoLO0brPdwlBpqVWTL/ph6ck81tGyO4ip04RUDep+C/l/7FRu
         W2LjTzsbuI8ruRE3Gi6bVZEQlekoqv0h6XuYzx/F5koBG1+j27E3pqlKbjK+DVTw+2Tx
         3870W/7MF2shcTD/l38kDCvoSBeSTjFmA4eFXOXZUkXAqv7GdsbUMkCu4Vq4JxWCvFfE
         AtgCsO+iW8neY2NZIqWxJvEvPpIkFxxVTKQ+tuuXW90IVSFqLm3lR4sE4//BtFevilzm
         CogO9t15EX8CgPof0uNHFqfj4OKUuXN+/sy28mm+efcTJSo2GjPGEvYPpggd47+Lhyrl
         fXzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MHApnVByS02AaUFkjSPlRVvJbIWzt6+ubFG4VCT8Rro=;
        b=NXxKGVxCRtE2zBnaXuRIpsqUAUVSmR9cBzSi7ldI1I+LQBzNoa2GEwatSQNPrgIJ//
         Y+mNl7hVG8yfuljMHo+r86hJx/Sn8UcXwVTbxHF3Mc/rzYhR6lQlFdBJY5lKm7bKLHrI
         lmJLtUDORtHkhiTl1OxPvsimLtPlLbGHbFN6vMU19qJEBLjtElc2BBnbadRA/+qzX3mK
         UyuOnlxIHjw+Pl84vlr7MPZr2ZEAT1aCjRQfZqyYSRDf391kL7dScWkBRz5IKHVY0MZH
         dIOuELVYiHK/YGvZvauEduzSV7IaPx3VIWOt2mn0JZm/4dxFRG5m98xvunSOQdm5j5BJ
         DCaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iz5mJR5P;
       spf=pass (google.com: domain of 3rbebxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rBebXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id d22si367271ooj.1.2020.10.29.12.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbebxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id z22so2525925qtn.15
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:41 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4512:: with SMTP id
 k18mr5677286qvu.5.1603999660819; Thu, 29 Oct 2020 12:27:40 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:59 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <61a81b0d782fcf0581c8c20a0cad4df38aec0954.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 38/40] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Iz5mJR5P;       spf=pass
 (google.com: domain of 3rbebxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rBebXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 11dbd880e6c0..50e4ac389e85 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/61a81b0d782fcf0581c8c20a0cad4df38aec0954.1603999489.git.andreyknvl%40google.com.
