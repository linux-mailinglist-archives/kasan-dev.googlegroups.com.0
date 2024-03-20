Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJHQ5KXQMGQECXDZLIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 96DD7880F7D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:19:18 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1e0115ce0c4sf42735475ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:19:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710929957; cv=pass;
        d=google.com; s=arc-20160816;
        b=01iCVHZTXaQV0NULMdpP89t7bFIYPYqLPhPzcdo441LboEvX5usQ21aUTd+Tcbzz8P
         K1S/cqJ0h23M9E93J5MJQ7nhr5vN3i59+PlFkVl38zeNlmL3WzAoR0GXpGsF42UnxZ4H
         C4PDrXMRab15ScXubQYrw6PVIRzvd4lSaYxP/mfHcPf1APxwUbzu1glkb2YdZVVk8qXO
         um4tnSgsAqT8PqapuE24RZf8VyoUinhVkg8xUSzvxiozZ49sWCyw6NFGbGTpPuAgpWv5
         8MuR2FhsfaPH3YcikO1F3/UxWn1z5hFZr2RPlrzE2sSSVCr/tGnqGlgTVSJNNgbmPw2H
         mzfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dn2oJvxxSUq9OGIujsQHPZu79L8pFlB7hjS74SPd0Pc=;
        fh=cEgghQNm83sKhtABPFIVujU0WRVnVT/dyoF0KadThNQ=;
        b=r3tRami0d0uzUJ/7RZeNb0s3ncpvu4QtLDETCQBx6a21BYDTA07ridP7B5HElltLkJ
         M6kp3McjendN5eX8BeERH0bUGAk/Gfm7gm12XAfaECwVTL/WoLOEBMcKv5EqR9xfbEUN
         4oEIt8D7qz1T4XUVsy53ofEVRlMNzlQUoZDTWavpghjFWlbvJHnefXEzEKF3lytORUHH
         lIYOcHKP5cGHQbkULxzjXi4680xZiRs9O5iLFQgRywHjkFlgMEQ0dNkVeSXgBEvqtjS0
         P2eb8e/UYk7epGkLGA0AWo6q5NhZy4v4pWqOGp9tReV5x9ZMMzvyk8r9YeSzCGuiBM8u
         2jOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Egd18ekL;
       spf=pass (google.com: domain of 3i7j6zqykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3I7j6ZQYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710929957; x=1711534757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dn2oJvxxSUq9OGIujsQHPZu79L8pFlB7hjS74SPd0Pc=;
        b=PdhYa1zjptUpZ3cb6vRenKbjZCxJ8148PQHoQ8Z4Lry92Qouf6d86YlIHL4nrhI5r0
         HOXplK//2yzkQ/oUN2p0W5iYnJZRbX1sT3kFdkyWStf+4tGWYId67sCdrhbRJwAz5J45
         CCkl+xjh+cw9ZKLivkDZdCGrAZ+BKZ7G+5rL4J+EIIH8VLpZT4EHD5IZ3y7ae1LPVjX4
         9NOSTTutqe9YzWBrhMMEDO+k2qjD921qzQixsiH6z0fHbB3n3EBVpSJ77UM3ZtM3Dxaq
         hnNpMDMJow/3KANT6yBACITuGwIy2Xb+xKsTy1qq6o+IlJeNTNwpL6iwu8WJsBk2vltz
         EOaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710929957; x=1711534757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dn2oJvxxSUq9OGIujsQHPZu79L8pFlB7hjS74SPd0Pc=;
        b=I9Zgzyfwz/5JnRH6Me9ZIcxxBV5LDqokp/oDhj0NOWqks076NoaWn7kW3B/Kgf6NrJ
         XTZ0w3LXC1zTx7KopONDAgo6DK+n0ymKRW4RNmZDUukYJcmlPZu+2+vPd4cAL+Q/Bv38
         gly9QiOWt01ICpKvYhNfmtb9qVjJB0cn7Y6BN3pF0iY3N8vT+y+9OBszES07PR0NNC9I
         Nswyu2YqcjSmIZ83CrAfnBTAVoZeEZgbHhukBgJ3fxV7OAvqzWTxDjIv1cgcyjCirFqG
         WEUh4bQDV3irnKgyhxw8MBzoWDZVIc5Ic+3G5CJU9L25x2Ju2qNGcqzLIt04m1I0YHsl
         kH3Q==
X-Forwarded-Encrypted: i=2; AJvYcCUaMbkRjEaM7AItifNEa2hsLOX7NOooU6Ell5+Zt4WkQ8zo8mFFehNFw+B0gGnksP++bO2SY8RTiVp1QLYZdlukN/YklBv8Zw==
X-Gm-Message-State: AOJu0YwJ66p0EC6EeoDxgud5BwEwnBeSCV5zpSWqCg2UoBgPYuAM1vCC
	dNGZ/QXj01HZJpgZgjERX9sMt4GwPCjjkYjOPYJxYNJYIAl1vlEG
X-Google-Smtp-Source: AGHT+IHAObDyZhIDoBktYHfLBTvygdkx1gtaN80d0Coaf2+H0mozVh5PfJI80qb8e4udrcVGu4v5uw==
X-Received: by 2002:a17:903:192:b0:1e0:3347:5bf with SMTP id z18-20020a170903019200b001e0334705bfmr2097342plg.37.1710929956817;
        Wed, 20 Mar 2024 03:19:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ceca:b0:1dd:ba2c:c1cf with SMTP id
 d10-20020a170902ceca00b001ddba2cc1cfls5912623plg.1.-pod-prod-06-us; Wed, 20
 Mar 2024 03:19:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUs2hg6cN0PXJMn0c8/syNk/uX57H3Fxwu7qMp9/Tnr66CF/Dwh8UuODn4fCCqVp7dM5YIEz5FuusapNV2dtAuQyj8Pd4Kh7rhmfw==
X-Received: by 2002:a17:902:f789:b0:1dd:7e30:4b15 with SMTP id q9-20020a170902f78900b001dd7e304b15mr2311515pln.29.1710929955654;
        Wed, 20 Mar 2024 03:19:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710929955; cv=none;
        d=google.com; s=arc-20160816;
        b=xNkXeWIRRohysLhJPBfvRzzTxZmrnGvQOWSaPo+LZx2xl7+1tot3CSTYJXscMDlmf2
         I4LZiZBqDGQmPuOY/dOCZFHZNhHJSaFiYmC2J/OgZ1Sy+Duwh4sCq/Ud4rFeA4+Z40Av
         COFI7brhhDpOROTe1cvk1pVL8vVhYUsOrdxY3hR9YEXtSEKXT7sp/qvpNC+9VkvkcDjM
         RUMA20jIu01NTjxKe30/7FzSfSL373/0ocjCUdEdSfZo0N/wJ6Q4QC75kIfNHR12uN/3
         BXUN6itFVfVeXqEAzgif7B33Nqcu+D2QjakoyPjUmGfWGk2mHOtCJCBPwHOsOA5YkM38
         Lo7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r71MCuDGNYKDimxiIJKs3mOhEvECUDV+QG0xkV6mxh0=;
        fh=VZ7ett4/l8rfC982i32JzbqJELxzGso6zmP/fgqSkd8=;
        b=v8maC6vjxVUaH66Xb99K2TuV6EWB5sZzbiNO7wh1pxQPN+G8tEBGQ21gj3fcp5jVRY
         si3Q4BV5VzjsgG4JEMxJTaYM87ATw8AtXehnJqbpF0wksPjP/zBu0tZe2Nveu+gZBgE4
         Xb7UCq1qd+YUT4hjEhdNMiAMsxw+lE3YT0DsDjSEczPLA9LmDA5aGvHAbbikz+cpqYw9
         1oBaiB1CdodmsPL67ZlpG8Eh+RcknRasajbThoG+HD/xJmkKrHhqQwMC5StZaNdu66Ki
         Rpz+p0jjJIKG5WIFuFDXhPoct9KoKveKdU43e762Py2LMC4+D51iOlp1yWnLtI2/xFI3
         JcGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Egd18ekL;
       spf=pass (google.com: domain of 3i7j6zqykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3I7j6ZQYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e9-20020a170902f10900b001dddaace148si1063049plb.7.2024.03.20.03.19.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 03:19:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i7j6zqykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dccc49ef73eso8490342276.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 03:19:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUcvVm13SPyErbLLqhUuVQUNRY8gMTfDmVSEB+9hiDTX/bmcJiyGu2U/3/9K0/B22H7jSeTxgvIxTWk5c6i1+7SzQwFnNxorYKXOQ==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a05:6902:1b85:b0:dc2:2ace:860 with SMTP id
 ei5-20020a0569021b8500b00dc22ace0860mr915079ybb.2.1710929955165; Wed, 20 Mar
 2024 03:19:15 -0700 (PDT)
Date: Wed, 20 Mar 2024 11:18:51 +0100
In-Reply-To: <20240320101851.2589698-1-glider@google.com>
Mime-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240320101851.2589698-3-glider@google.com>
Subject: [PATCH v2 3/3] x86: call instrumentation hooks from copy_mc.c
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Egd18ekL;       spf=pass
 (google.com: domain of 3i7j6zqykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3I7j6ZQYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Memory accesses in copy_mc_to_kernel() and copy_mc_to_user() are performed
by assembly routines and are invisible to KASAN, KCSAN, and KMSAN.
Add hooks from instrumentation.h to tell the tools these functions have
memcpy/copy_from_user semantics.

The call to copy_mc_fragile() in copy_mc_fragile_handle_tail() is left
intact, because the latter is only called from the assembly implementation
of copy_mc_fragile(), so the memory accesses in it are covered by the
instrumentation in copy_mc_to_kernel() and copy_mc_to_user().

Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>

---
v2:
 - as requested by Linus Torvalds, move the instrumentation outside the
   uaccess section
---
 arch/x86/lib/copy_mc.c | 21 +++++++++++++++++----
 1 file changed, 17 insertions(+), 4 deletions(-)

diff --git a/arch/x86/lib/copy_mc.c b/arch/x86/lib/copy_mc.c
index 6e8b7e600def5..97e88e58567bf 100644
--- a/arch/x86/lib/copy_mc.c
+++ b/arch/x86/lib/copy_mc.c
@@ -4,6 +4,7 @@
 #include <linux/jump_label.h>
 #include <linux/uaccess.h>
 #include <linux/export.h>
+#include <linux/instrumented.h>
 #include <linux/string.h>
 #include <linux/types.h>
 
@@ -61,10 +62,20 @@ unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned
  */
 unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
 {
-	if (copy_mc_fragile_enabled)
-		return copy_mc_fragile(dst, src, len);
-	if (static_cpu_has(X86_FEATURE_ERMS))
-		return copy_mc_enhanced_fast_string(dst, src, len);
+	unsigned long ret;
+
+	if (copy_mc_fragile_enabled) {
+		instrument_memcpy_before(dst, src, len);
+		ret = copy_mc_fragile(dst, src, len);
+		instrument_memcpy_after(dst, src, len, ret);
+		return ret;
+	}
+	if (static_cpu_has(X86_FEATURE_ERMS)) {
+		instrument_memcpy_before(dst, src, len);
+		ret = copy_mc_enhanced_fast_string(dst, src, len);
+		instrument_memcpy_after(dst, src, len, ret);
+		return ret;
+	}
 	memcpy(dst, src, len);
 	return 0;
 }
@@ -75,6 +86,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
 	unsigned long ret;
 
 	if (copy_mc_fragile_enabled) {
+		instrument_copy_to_user(dst, src, len);
 		__uaccess_begin();
 		ret = copy_mc_fragile((__force void *)dst, src, len);
 		__uaccess_end();
@@ -82,6 +94,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
 	}
 
 	if (static_cpu_has(X86_FEATURE_ERMS)) {
+		instrument_copy_to_user(dst, src, len);
 		__uaccess_begin();
 		ret = copy_mc_enhanced_fast_string((__force void *)dst, src, len);
 		__uaccess_end();
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240320101851.2589698-3-glider%40google.com.
