Return-Path: <kasan-dev+bncBDCO5FWBMEIOVGEC6ICRUBFFWGZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 02314156CF1
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Feb 2020 23:49:15 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id m4sf2351691wmi.5
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 14:49:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581288554; cv=pass;
        d=google.com; s=arc-20160816;
        b=cskUy+QF8UsuMwnp+kTdJLMsF/LNU3uo6bYBQ5v/MVrdZZOdil5hAL1NIyyVAUcyXS
         qTCBGoFScUDJFF2aIaK3IvHgPpw7lEVU6G/tceN7hkJ5hMUPSbAJfKv0+xX4HkDP8J4t
         BTFobZAm3wwg/1o/rw41bVMgBrJKBzfM+t6x+3TzaBu2arpg5FpTHhs9fyrWD61h/3hJ
         hQD1K2ncawxRWLyCnRB9WvUf+pYePmWVxa3SMVzvP0vnBWWYvDpmNzOuXoNTREGs+xKe
         +tm/kW6QLKYasI0IwHG+2+6WldplXVMUHelbQKAh0bCHjx0/zlSJt56rNA9i7xi8GL1F
         d1nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FVvSQTzvKtGqxK+u1i1S3L+ZCZm6So0tXK1AcShH7VM=;
        b=El+KWhXyRCTuOar1wUD19Y5H7Zcg14Y7MHIpJkZHmANr9FZxq/kWKQxwe6OoXAHLy8
         lVC48Egvxc7UWY/pXvsy4sx+Swe01KfnBp5FMz+YBmziOfN5x5U6JXq3NJmJpFaeuyio
         xYJ4JAUknoC8KG56qk9/98E77sVDJ2mELK9wTsmhoKSa2My6JW6rNlTx6lKkcizyssJQ
         Fwo/jEWQ3NP2h61daF51te8lsBXuYQyS28JqEEONBdyYqDKNGlV7d0IeexX/wF2Msg3N
         OWs4ATZaNt+uQoGVPAChEJ6tHYW1ApvvFvsotSRujR40SxnaOSJtEPtheCKrkbGadUyS
         zTew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=dkdMkDwP;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FVvSQTzvKtGqxK+u1i1S3L+ZCZm6So0tXK1AcShH7VM=;
        b=JJSqDliF1crBq0/ceoNX2wy8FCb6mbg+uLucw1jMXnXVPVbegn1graoytiwt5s5+K6
         7BMaRf0evhZKPt2/EHdJvwYAEqlBVLBmZkd/h0d00N51D4OsetYsLu83dZgMQPjFmWJp
         vpUstBMBNkK9xzn4QfP6O6jq8o2Upor7DEDxnDNVmS+lBqjXRGu/K0Kb5JnDg/DbvJtl
         SInSLtqMu2b3E4Eja1HnKqZ+OsNOWiNf4T5zvTwwUMDfdBx1Cs+B5etADxjBCYv+5c0Z
         F40lhUkG8BwgagksAboP1gLci9P2ntJr5MWIvPyoq8aBS+pB9v2G1gXw8MeKo20fCNuQ
         ZcnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FVvSQTzvKtGqxK+u1i1S3L+ZCZm6So0tXK1AcShH7VM=;
        b=C062yPuQMEnWIunRwaNcgfvxXh0IHSw0X4YLbyKgeenfh6AW0B4ueKDyyc53Tn/yh/
         /B8snXLZc+H42kYQB2IIe2YLkehsMtULR9GlecGgldgi9X9Oy0wV7YFYemfLkIBmFqJS
         pYLHyS1Ny49Ai4SsEHI8khTFerdl1Tl70sjRU4PFXzxHhQnS7dgHb4pX3t2DtQuarx+8
         idQv2ETNVWWzIkK8do/Dwzf/kvHgiSVpsXeRFEAfqXm5niZ/zOZpKheHpo3OKO3O2Ve1
         ApYfE580qyLbdpzJub7V5SGNGnbE6nYOXLMt80b//tb9j9pXalDHM6NbwwzBBUtJElN7
         nQBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FVvSQTzvKtGqxK+u1i1S3L+ZCZm6So0tXK1AcShH7VM=;
        b=fkqB8ExpZ+F0whX8Hrm3n7SL1B0ZlbeuxNA06/WHMnT7LN7Z4kwtulreiEvq28Lkfm
         B+qGo4tEEhOcvDww8ZhSdx61a6VuVTy6v/RurycAtWbcSxuR7fD/f8SQnr6aWrxDkOmw
         KEDhZ8lSgYQ1BVBdchjYIl10znGNDLFmMNr+hneAsVAnlazvaml/D9d2H8a7Ompd5kRF
         hzl2IO7M9+niy8c/qUj0MF0xT3ARivPPcZwhPbwalml5XHPYCS+Uc4hBROs4SFiiSioY
         FA1WtEgrCP+XfX/VcQ/pTfbh0CmfxlA/QUv1AvNSp8VdKVg/jWu+dE+MCNQ0z2OcJxsY
         HXOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVaGzK3V3VTwBQq+pNy+aT24gvySEcj+Ht7XimBGy8Zc/P1C9l4
	FoI7LZk0idLpQNbogniRHWA=
X-Google-Smtp-Source: APXvYqzfA1t63RmnLICTo5H75f76HRyfnAHFf7sHvmm7h4n5wMrkVOq3wXlK9DdRJGLfwb+gGUtaPQ==
X-Received: by 2002:a7b:cb42:: with SMTP id v2mr11558654wmj.170.1581288554782;
        Sun, 09 Feb 2020 14:49:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:247:: with SMTP id 7ls13324322wmj.3.canary-gmail;
 Sun, 09 Feb 2020 14:49:14 -0800 (PST)
X-Received: by 2002:a05:600c:2107:: with SMTP id u7mr11460654wml.180.1581288554169;
        Sun, 09 Feb 2020 14:49:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581288554; cv=none;
        d=google.com; s=arc-20160816;
        b=h3NvTm8Nv/SVpqBAz9e55UcN1iWKemdWZiX9kTC2dWboKMohnthcSJz9rASFGZMgbO
         /hY9MYusNroZz5AF3lzG3vVWwcjkuyrs2nZvDrw9gWimHmy28yV8jkbINWfgH+FfVH8G
         68iI7Gv5aM7mFIHz0G8PoW5aM4GhnCakPJDDSuPlQtQawyBcQlEy22M4EAHPhibftBhX
         GhaZ4vMdd1feQFfrqwYmipUn82lGso86PgvcHaqpuVbrOxfetIRSBK51i0sceL+51YzE
         YYryUKIbCzHz+CkNkU/q2zg5J426qd0JeDBJgiQh9Nu757ANlJ2y6aJlUmVzJHpjzlZD
         mNXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U5nFVCPFUZVGZ9tjWv0oFjWi+FTaJwKQRZfFYGfUUUg=;
        b=lw3/cUTqWaZ1TfSr0/i5t9aEhdAh+zI4Eo6EPrVFtJJ1FrKOGJSu4i4X2pe9QRfPTg
         7o6k+2bznx76baWKCKAPUBTQeU+ZF9R9ePihpfjyorKNo3asNQWyZeawVgn0wUraF09Z
         1Wqy0R84wg1YAAXHw+7JKV52Hhvmyy5yMWeVwGWQDK1UaEBACfHLR6oo2QBmvfeMEqbo
         qQ8QBcoLGQTx9suASpmdYICKrakORx8Ww6fiKhA3zsLS+MWv/uiee/Xm8yZjoSz6PCBN
         LNGTJlXcvzkp1kFK8H8rVohrOxw6DX7Kjgquj+OayNxOWTmdzlMGKAfBD/I5X/TExEA6
         F/MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=dkdMkDwP;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id d191si781105wmd.2.2020.02.09.14.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 14:49:14 -0800 (PST)
Received-SPF: pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id z7so5197540wrl.13
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 14:49:14 -0800 (PST)
X-Received: by 2002:a5d:448c:: with SMTP id j12mr12604749wrq.125.1581288553707;
        Sun, 09 Feb 2020 14:49:13 -0800 (PST)
Received: from ninjahost.lan (host-2-102-13-223.as13285.net. [2.102.13.223])
        by smtp.googlemail.com with ESMTPSA id k10sm13694884wrd.68.2020.02.09.14.49.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Feb 2020 14:49:13 -0800 (PST)
From: Jules Irenge <jbi.octave@gmail.com>
To: boqun.feng@gmail.com
Cc: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	aryabinin@virtuozzo.com,
	Jules Irenge <jbi.octave@gmail.com>
Subject: [PATCH 10/11] kasan: add missing annotation for end_report()
Date: Sun,  9 Feb 2020 22:49:04 +0000
Message-Id: <38efa7c3a66dd686be64d149e198f2fddc3e7383.1581282103.git.jbi.octave@gmail.com>
X-Mailer: git-send-email 2.24.1
In-Reply-To: <cover.1581282103.git.jbi.octave@gmail.com>
References: <0/11> <cover.1581282103.git.jbi.octave@gmail.com>
MIME-Version: 1.0
X-Original-Sender: jbi.octave@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=dkdMkDwP;       spf=pass
 (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Sparse reports a warning at end_report()

warning: context imbalance in end_report() - unexpected lock

The root cause is a missing annotation at end_report()

Add the missing annotation __releases(&report_lock)

Signed-off-by: Jules Irenge <jbi.octave@gmail.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5451624c4e09..8adaa4eaee31 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -87,7 +87,7 @@ static void start_report(unsigned long *flags) __acquires(&report_lock)
 	pr_err("==================================================================\n");
 }
 
-static void end_report(unsigned long *flags)
+static void end_report(unsigned long *flags)  __releases(&report_lock)
 {
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
-- 
2.24.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38efa7c3a66dd686be64d149e198f2fddc3e7383.1581282103.git.jbi.octave%40gmail.com.
