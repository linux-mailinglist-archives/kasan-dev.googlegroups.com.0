Return-Path: <kasan-dev+bncBCS4VDMYRUNBBAFK4SGQMGQEVWLYTZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B53474D98
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:49 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id x132-20020a1f7c8a000000b002f59112b3d5sf10313871vkc.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519488; cv=pass;
        d=google.com; s=arc-20160816;
        b=FAV7m6gOShdgfeza1bP+9mHI3w0ndjBiDWsVRBgPQQN2xeKJmZ06TXeoeSzP6gqKCk
         3rJcK7PsLeAOs8Z32rtUjoHlx9WE4zCGv1GluKaycJjSiFgNr0KqhOC0xguj7dmSRjA3
         NhvT4086wSgOgD6byxsIX7GCuHVn+Fh9iDdbETMdf3cW5kMukZlF7gIFteWcDhAZiXRw
         CsZ2Uvfy5w2u3goBRvzSS8QvOfw7gSs5Jd1y1fDcEnYUHJIfKXxQUxvMNEPOCmqAcw82
         iLIpB+rcjUGNMpw5bIa+WPk/vUHZXHknMUnCG+h94OzVIYKYIq+4N2kNT+KoOhIn1eTW
         2jpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=fN2XFk0bXSsd9pN6NKRyV4oVIeM3z8e82BT3gA2caq4=;
        b=C37aUHtKsbj4QIE5RoVFtJVgKpeT5qPm4aTrMzj4KdzzuzG06uuh3W6O9ltFZf7u4m
         0nQn7qdfYMEfxr7rmf5x/Qh+s+O0AA+yA9uEAENWp3qldLHKgQ2pKy53L6LicZX22YgZ
         GjBbb3XikxXay75KL0VVbQg52+718MvMqIf4p6v6BRD6QpSJaNeAjgl4FIuzKuFwog+/
         enSz6s6VvEWlsjeEDzYCkgXRMe18v9/w5lLVkjUCR5eFt+5lMnC1/ndM5QbzOEckPGNk
         dzC6IyJjTTCPXLO2CJBu1sum4DUIWov+jW4E62dtEIAOTEDuUJuBGDitE7O3VzdbD06P
         xpqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qA9GKVzB;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fN2XFk0bXSsd9pN6NKRyV4oVIeM3z8e82BT3gA2caq4=;
        b=V3VyYGCw4zBx5pIiqkmIySaqco6aqbepjEc+vvMCeZGIvra5+yFieesi2cMOaBkF87
         GgZDwci7o0n74qztHEWPxElU54KJvp5G2nZcrFSi+/OGEH2Ed+LcE1l7Q//7qKiBeYjz
         3qBVZk5jFXUFPmhlVAxkV4yuESS61AVU1jYrUtcjZCbFAX2Z4jNj1Xp1BY+IqKsyB/RS
         Rue62lOxc8sIiosMYG7FIFO02uNvCSrVJL385PB4i+GhCaiQXBX0ShAyrcFUUSTx99g+
         GrnczMMtdkGo+HqBoFjf7CZtJUG2cMADL0acyQt6nOgFHEsy3WtKIb+ZDCWjNShsn/hT
         uncw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fN2XFk0bXSsd9pN6NKRyV4oVIeM3z8e82BT3gA2caq4=;
        b=mjo7mhUcNwktPWoNabRhKWJqxC85xCNBl2pqiKxEp5CRs9A+4RVYTtx6GXJ9bEEgDE
         P6PFbx5F9MwByBspJKB1fcg93aacBffQdtjdp4fQOwOYbftw9NVOK7cX/n3fyAU4z93T
         vkVyJ/jXItM5BfARPCmqZ8rSYEaClTx+hXqXUz0alUM1qpRlKacw7nNPYLjh827ww+ey
         F0hMBGMKVZEyXQE7HFlC1v1jGuayRGlOwJdiZ83DaSmX5mpziFy6qU9tHQ9TU+7DhTie
         39CbwV38MKCxlkJ2dNFoZv5Uy6w4v9xogCgYGz5/GLdT18xae5H/2TUCWLeylf8wFGnq
         h00Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eVnY/tMmpDwLnW/iHuTHXbkdHqgW5S+MTnZKQrTLN1oqsoout
	WMlf9DosuLJFip/0jEwXyVo=
X-Google-Smtp-Source: ABdhPJyoKfwEONowcHFPP3q6LRtoEbTbGWtOhanyO64tWjf9zfyIeXOPTdMaPDH70QJMQZ/E/VpFZw==
X-Received: by 2002:a67:d893:: with SMTP id f19mr1626991vsj.39.1639519488721;
        Tue, 14 Dec 2021 14:04:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f15a:: with SMTP id t26ls10581vsm.7.gmail; Tue, 14 Dec
 2021 14:04:48 -0800 (PST)
X-Received: by 2002:a67:af03:: with SMTP id v3mr1587118vsl.59.1639519488199;
        Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519488; cv=none;
        d=google.com; s=arc-20160816;
        b=czwulRAa8kms4QQrX0p50H29hyV6IoBzkjY20FSqGtsFyHUx4jAPv7+iCwltXLv1HV
         gVxCXr2n6ySOb1w/vx0bjwey0NiDSmhwGJi5DefQhWotIioQNlBrPVxFSpldoO6lLvhM
         +WXmfI/MQq+71FSh8+NCYGie/9RgeCqO8UyCJTpvhKTeE+K0IT1KvdbX3PRo2lcZPoS1
         ePNfpc7nTcrSQMDDea0Dv1Zn+4E2J4R2oiJ4Tw22opU5ME+wrME2hAHPv+PRR2eVhcxW
         aQWee/LZwX7YG66tG1eCD++XBazPxe0d6f4WWs8lgKPLUpQbO6ULQhNJ7U4XLmCO3/aa
         frWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eefv5z8CIYYAcK5bCjWgpwAJEoJArxDLYlprxcYeAEI=;
        b=0G/NYg+S9fKsWofIF4TQEIJoU7pYmXwA4CZZilXEA9nM/GTeMeHqnyWSJ0zFv7HTNa
         ba0NviSrB4MLPW6xmk6QXTA06Q1CV0vkZSh7j5arOQhnfsg/TnNoyzkCzK2CK6wCjkfF
         LZjs98Yut2AlukD7uW6eBMiWq+OF31EwKd2UfNy1aRR3Pxc8pBtfIGapRPicEpHUMe9l
         IogEZ6xzZD/R+hCuXgnXIrP8ePYA61EGi7whxnZUdpQsj22wiovsI6TWlzOZgPtTyulh
         yNV2sxztCvuERLCD5YqV03M/NoqRvNvXxLiD54qn8PjeGVRMzmVb4IhpzaAH75qLHkIy
         HiKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qA9GKVzB;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id q25si8250vko.0.2021.12.14.14.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:48 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 2FC55CE1B0C;
	Tue, 14 Dec 2021 22:04:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0947C3461C;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 70CF25C00E3; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 12/29] kcsan: Ignore GCC 11+ warnings about TSan runtime support
Date: Tue, 14 Dec 2021 14:04:22 -0800
Message-Id: <20211214220439.2236564-12-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qA9GKVzB;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

GCC 11 has introduced a new warning option, -Wtsan [1], to warn about
unsupported operations in the TSan runtime. But KCSAN !=3D TSan runtime,
so none of the warnings apply.

[1] https://gcc.gnu.org/onlinedocs/gcc-11.1.0/gcc/Warning-Options.html

Ignore the warnings.

Currently the warning only fires in the test for __atomic_thread_fence():

kernel/kcsan/kcsan_test.c: In function =E2=80=98test_atomic_builtins=E2=80=
=99:
kernel/kcsan/kcsan_test.c:1234:17: warning: =E2=80=98atomic_thread_fence=E2=
=80=99 is not supported with =E2=80=98-fsanitize=3Dthread=E2=80=99 [-Wtsan]
 1234 |                 __atomic_thread_fence(__ATOMIC_SEQ_CST);
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

which exists to ensure the KCSAN runtime keeps supporting the builtin
instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 scripts/Makefile.kcsan | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 4c7f0d282e42f..19f693b68a968 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,12 @@ kcsan-cflags :=3D -fsanitize=3Dthread -fno-optimize-sibl=
ing-calls \
 	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=3D1),$(c=
all cc-option,$(call cc-param,tsan-instrument-read-before-write=3D1))) \
 	$(call cc-param,tsan-distinguish-volatile=3D1)
=20
+ifdef CONFIG_CC_IS_GCC
+# GCC started warning about operations unsupported by the TSan runtime. Bu=
t
+# KCSAN !=3D TSan, so just ignore these warnings.
+kcsan-cflags +=3D -Wno-tsan
+endif
+
 ifndef CONFIG_KCSAN_WEAK_MEMORY
 kcsan-cflags +=3D $(call cc-option,$(call cc-param,tsan-instrument-func-en=
try-exit=3D0))
 endif
--=20
2.31.1.189.g2e36527f23

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20211214220439.2236564-12-paulmck%40kernel.org.
