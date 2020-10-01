Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKGE3H5QKGQEXUHWN5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 85DCB280B09
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:36 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id a12sf120641wrg.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593896; cv=pass;
        d=google.com; s=arc-20160816;
        b=AyzGXxbCh+ZzEm8XiRlyY+3OcqNlzWPgS02cBd/mEZNKwrlDxSXBb8vcSUrr7fbmeZ
         RFAJb73g0ahdFEDr1nsvvuxx5+lmVVIib3woS+6USPlL6CHzNvYF1JCvWH0btukNG3lc
         /Vxn9BD0/1O1NHwBrWhZT1VF/AswKlvA2dB038cbXKTPZAiAwJ62HiKmpzVs1hhq1TBf
         U/PDuZoLSq14No4Y0b1QJ5NFaSSMAC/+a7vkuiV22NkxkWSlaJJkBRVdjH7PiJSfaTuL
         2YDjKvIJ6NpCT02tt1+TEHLxMHn3ZwEJwtKvUprZ/j9GWNZgdgghvr2CIyS5Ue7m/zsa
         shzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5VDadDRy2nc5aoxERVKIxDfNmpGljtP9pkZb/+kPPgY=;
        b=FNd1Ld9QvjUODY+pdPQM7/5aSczH9o3JfssVIXQYMR0usYlCBzc26g49eqfCQpY+rK
         qs0GUkL+CkfBUkumJLmder+9D1Vpxd/MM4lx50LU7/1Fzal5a9Pl9BfKliiBvRe7TRx1
         NNTgBUyVuO1JaId+UM2o9wkrlpBHRLzfhsgaRdcBNUJLplxCxizfwS18scKhYfK0425f
         QgGdV1bvk4DPYFFzXqAY4d/UL7Me1+qnaAnsvibFRsN+gwnQpI4pxRlY4ICn0FcFI889
         JUGCOrjVUUXGpq9DKJJP3cNUbr7yyVSOj8dIe11iXE11qFbNzL427SX73jE1QTdPJzAP
         ffRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=swpCHanQ;
       spf=pass (google.com: domain of 3j2j2xwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3J2J2XwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5VDadDRy2nc5aoxERVKIxDfNmpGljtP9pkZb/+kPPgY=;
        b=UnZxa337Za73XKuX2K5/l+JrLXiCXWuLG4YcldTr+eXzYMcQDAs3wBLDRDRL+5Epcp
         h65rkeDx5KHPakBQdlHg3+/cgIiI7aPiday4Tm9YX4hysz9mQzWGlhtOWbJp/al9gJV9
         zNzTQx5g74T0+mYdVpdqnzXr3p2ckvApUf6km0PBqVuEe6F8VNJqTd1PVaW32vnPpVcY
         IguaMYr906mH77FKOEDKxbBl4XsHMH7IUrcOuga4fZ6aXmSVuZeJQdc/72aEQevXjL1k
         4++HmjoxURF/mwVIMyWOhEoDdT/PoIJVHbAfVv5QKR+kW1GEagya8CRb0hjfg9prgM6c
         LPOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5VDadDRy2nc5aoxERVKIxDfNmpGljtP9pkZb/+kPPgY=;
        b=GmxEU0Mihfm41iVXhfEzjytENiwYez5wTSDEZ8sci3xIjUiH9+4uf8uLxRuv5OZCWS
         5Gk7wGpO0ge6LwnuU1WLDfTgpYCD6+nQGfJwk5EwknyiS6fmjbxo0r6edXKCD61q8B4J
         5eshzQD+GU5hQu/QctbpfxWvG6vxmjnZjDO5rr/oDLqfuYQCSVb3W18gBjBA5j9TP0Wd
         hm7FIw8eujnG74YP9V3Q2Ng8aZol4JnEkJOZtm5TpOXOWl7YBzENYb1XedVZvxm/LIY9
         h8kYAAv71UA+gRy77nSegH0RCS4qa7RCRSgAVaUgjVR0KS/RhBox5OFvNopt434kNLDF
         KmsQ==
X-Gm-Message-State: AOAM531o1Kq68Fjc17VRFj35Uir0s7S9j9nLYZiDZxGHxqzk0RtYwLN2
	caDwlOrRQlLdAOgOgSfDz+E=
X-Google-Smtp-Source: ABdhPJxeSRdJ1Hebm11jTMSNWxrhUZYP/Ht2R2yr6E32W0A6NgKhvoJKCVHR2IfDAo5VJmHspxGZbA==
X-Received: by 2002:adf:df81:: with SMTP id z1mr11934154wrl.9.1601593896277;
        Thu, 01 Oct 2020 16:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls3659850wmi.3.gmail; Thu, 01 Oct
 2020 16:11:35 -0700 (PDT)
X-Received: by 2002:a7b:c958:: with SMTP id i24mr2429631wml.50.1601593895559;
        Thu, 01 Oct 2020 16:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593895; cv=none;
        d=google.com; s=arc-20160816;
        b=j+FTVioJpbYeFoPDJlgf3PMfTSh/FIIKB9jhis1JfdpHypnUDGHHca6KqG0hcgScgp
         fvELreEWQMfWmmzUIeUN+6lBadJ6qqB9YehPoohB/mM1XmkdGI6C8d+TJJ1V1LmwvDT7
         vC/DB20Mdf6kkZg90OdC6Mr9mIopID0qXJQ4wvO/IS0KU3Lqzimn70Qaf7wv0ULKm35S
         GZ8XIMXji0lL/cG2KqOob7D3L6MKjhnidSlNVuBQnQfl4yR8i8lYv1uXf3e/7sOhoLc/
         LZZzxiuq8jkqsDnl8VViQNy2VnAtbvo8Um0Snmz2tTV9ypum6h7z8xR2IEzNXOmX6AqF
         jT+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=aHaqAGqhe3K0FS7ZJWcfKrDk8FNnWGrH4p9dPgIlLEI=;
        b=i4JHfbJQrrMEYpwp1mML5ueh0pFFcrLtlyVOElZexjUwIX3T21z7KRZDk4ChjbYo1W
         hyfJaGxDV05fqsc3dHyfSLJofFwJm7jJDnwn/tVrGEsahIiSGr24pYsDzRWyP2XJD1x5
         H9MfRIVs9sFAp6hgIMbdB8Ht278sZ/LobdG7PeQwPHte4l4gCUAN2+hRnA1lNqac4SBZ
         HA2lhvAeMxNNfc2j8/lKl3DDnwHQU1HGyLu29+WU7GQM5GU9CwdG8zcqTL2E+yCRS17D
         Cs0wSSlkMKw/rPdimAQ8EbEBr69g3LWX/qUclgvaTQtf0GSRdjJ58K4b1ucx/iKV3+/l
         IUsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=swpCHanQ;
       spf=pass (google.com: domain of 3j2j2xwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3J2J2XwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f3si131181wme.3.2020.10.01.16.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j2j2xwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y83so24209wmc.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:35 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2053:: with SMTP id
 p19mr2326483wmg.50.1601593895081; Thu, 01 Oct 2020 16:11:35 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:22 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <a8a68f89df9e516b8a09fe56abbe930b8f3e8a05.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 21/39] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=swpCHanQ;       spf=pass
 (google.com: domain of 3j2j2xwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3J2J2XwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e7450fbd0aa7..e875db8e1c86 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -131,7 +131,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a8a68f89df9e516b8a09fe56abbe930b8f3e8a05.1601593784.git.andreyknvl%40google.com.
