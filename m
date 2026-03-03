Return-Path: <kasan-dev+bncBC7JHAFRQMIRBSM4TPGQMGQEWOR53UI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yOj/CEzOpmntWQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7JHAFRQMIRBSM4TPGQMGQEWOR53UI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 13:04:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B73C11EEEF6
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 13:04:27 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-899f6e5b909sf146291336d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 04:04:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772539466; cv=pass;
        d=google.com; s=arc-20240605;
        b=jCHizOQHeG89W2x0Ox8fHqKxBuJhmkOmCA5Kpfo8ZFaYL+3BmfLNBnRfLkWWesQQyW
         5c3r1coUjSx9vnSEKR/mk8CdY268hXEVBhI06smOOVi/jVUwAp08mrOczhWZBe1wgvum
         79MomHzuKq6UdpaIJY14CmfeEiTIY5Y/5jsib1CPJyh+ALGvJMmgaU7Kj5nmg1h/lIP2
         pG3De55kLMuJlI2DXVrD3TXC5NRnPrcb9D474E/0vz37MFqtCaMTN/pLcnMJJdaB/0t3
         2kmJL8lV/OK+VY+Nj8PnM46tVgXz5bq9lSledisQCkDXK2J+VODa0Vnoeti+Jpajb1H0
         kIUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=T8IvYwitSM3OT+WrRPBAeNMeFiqApvohzqcmapS1XPQ=;
        fh=YrbkQorNOKVRc2TAMH0DqJ+PVxC/fW+XAmXmJeVeHxs=;
        b=gdER+LuEgKZBuW0mWD8OmEAXcVoJDwi0ZTQbqqUGlU9zUf95tMAIuzXx/Lgzh4Tqwf
         EUMq3mO0hRSIiB7JxFHHgiBgWbuSMpEOiijPMnNh9BxbjI7rE3lLu5qcDemRyBajRQk0
         IvZoTytjuyO0J8yBtAUnPwt6T3aSvSizvunzmzoiDJEJwMryqA01zxGvpM/32+FQWhua
         4L/1e12E1h8ujDD2TN72vVOdZBe6vE+2MP/NA9wqUVGsiZZMVDCBoQ11ahwa/cVTgyt+
         9u4oxK9llNcwQpK67MB7Os8gbO7NtSHUvzgeOtBQmg1kCNHBwZZqhfDK0283De78VKrN
         kYiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VPyUuNMv;
       spf=pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772539466; x=1773144266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T8IvYwitSM3OT+WrRPBAeNMeFiqApvohzqcmapS1XPQ=;
        b=SDRbtQleQMvLf/a9uT/y8MMa0RURqHe/a5a2HYPGSpUOjDSP+iHUEh4fpZw4iaYDHz
         qK0x0mTkPpzccthbqOKNvpLO/eQT93mP4WQVbfSrPX1SscweTy6NAsm3lk90ylH0ysd3
         NmKVC3nOJwKkY+N9OFHdOhUBcKQY3itg+y3PMYyeOyAeDXY5R8uI9xR7Xo5c+ICs+5+7
         feMAUXCQ3tnZbNQjldfBEVnaN64+GCbRNLadJw4dXY8mSsQrPTV2oNf366VPE3IkPRKO
         zmuHvYkBcQgLUVJv9yamUPfwlt56OB8fuJ3W1Tmxkyg9m/q4rDDROmNP5RcrWsbZ2ljx
         7m+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772539466; x=1773144266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T8IvYwitSM3OT+WrRPBAeNMeFiqApvohzqcmapS1XPQ=;
        b=tNWoGSMHmDaGFIuA8HtaHakNr/UstAv+U1JXDCwNP+qll83JIe3ez98Nx+ki+++aq3
         Z40bVfJytURUeze0EOH7vFFeUnYhb/2RlwgpqGE2s26fiNfk9Nz5rnZb61pcAKgAAj1Z
         aIvWg8ilkdYippyXhud0nqNWUR0eblRILQoXB3ozzIKZtq5cK70nsNcwblTTg3V3vazW
         0ETRDaGqSXj965txnNKITxxQDLZ6D9IN4KJs1SulO012cZhA6Hct18yqyxXVnhIDpD+w
         ZaegoEf/ArcHKDjA5dvvcB1lUtnGGxDPFUCDu6yHQpSWTmCxfl5zH7NRciTdOf0z5dBr
         Srkw==
X-Forwarded-Encrypted: i=2; AJvYcCVyn3ulxzDs8UUQuUTP7eLJfCOkuIN6cMA6VCJo8o85dLzBbz04C/DlR03l8Sd63rqCdtDtgg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0Pko+D08WFgziw7mO76rcm3s0LNCWAqVsWuLh++2O+AllAe1v
	AAXvHrBrArH2prRT2jKvumWcELrJk5K3cX7h6svIwtyQxRqVkUcagqin
X-Received: by 2002:a05:6214:4108:b0:899:f6b6:543f with SMTP id 6a1803df08f44-899f6b65750mr97599266d6.48.1772539466183;
        Tue, 03 Mar 2026 04:04:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FRKk6w1+EWJJAGll32k8Iw+OJ/BvwdPUfzN5Cls/M0kQ=="
Received: by 2002:a05:6214:5010:b0:89a:7f6:6d8c with SMTP id
 6a1803df08f44-89a07f66f37ls16680636d6.0.-pod-prod-03-us; Tue, 03 Mar 2026
 04:04:25 -0800 (PST)
X-Received: by 2002:a05:6102:3e95:b0:5fe:159f:2ca1 with SMTP id ada2fe7eead31-5ff323277e3mr5499613137.13.1772539465226;
        Tue, 03 Mar 2026 04:04:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772539465; cv=none;
        d=google.com; s=arc-20240605;
        b=AVW5zLoKNdenQyc5TWYYXgW2AEZXhx/ve1g4cjJi3nX1U4q2BzNfOoaQnLdk/97/c8
         ZS/sZiqiVKfn/Gh8EbrnRAcs0oiohiq4jkhA7FN2V0nruj4Z1xSNHZku+3hmBv74qkUA
         9uYwdZpiCrL+gjln/CcxvlJTktqk9QBFGHuVkkBh86sk+SF/T3zibW5NgMJQX5RAnLch
         HPV12C93xENOZZXAAVgT+tq7l/7dSyoXYp95CBm10CjB4S+DUDu3Imu+NbSC0AYojp7z
         fM6nBQiikZWNPTY7GJnM0Z2uZ5sIyjcJ0/3U+mruracxbP7Uf/yzDR0OuOAjLOk9/WL9
         5H/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hFvLeMSSg0It80Z00WRjb2O6RCM4XKLr+xbB68NPBC0=;
        fh=Zm/v4Z4vh1b+ecvYUn9C55V6rKshVGB+kw5FB/0tY9w=;
        b=HUXDb3G6kHKAO0gbDtxQSgsU4HtW6qzA8LzZturAEQ+hBtE+/5WEuA0A/rZ7mSbHEL
         OIJuOl+TxA3jO4kFBWpsbQKKuNW09puYquO710erDfDwqX3gJTsjLkkwkdyIm8Gh5Z3P
         JoqgGdDAOoQ0ibtP11jN7vN2EXcuTKG9sto2sJUZSrosoRXnJaIKh4fqehVeM7othDg5
         MfrI0jNflg4EFtgnn8wt6qXsTahvOhe+t+zVzKvji9MEm3LuwiLtOg75hxnyS8stvDrl
         qdPLtwRG36irZsjX/ugnd8qX2odjRGKiangT2dTMR8yWXipHQPUJXmulCNAJgZWw+0t+
         6L7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VPyUuNMv;
       spf=pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ff1e9ea5d7si526231137.4.2026.03.03.04.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Mar 2026 04:04:25 -0800 (PST)
Received-SPF: pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 35C4240337;
	Tue,  3 Mar 2026 12:04:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CCC09C19422;
	Tue,  3 Mar 2026 12:04:20 +0000 (UTC)
From: "'David Hildenbrand (Arm)' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	"David Hildenbrand (Arm)" <david@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Vlastimil Babka <vbabka@kernel.org>
Subject: [PATCH v1] kasan: docs: SLUB is the only remaining slab implementation
Date: Tue,  3 Mar 2026 13:04:16 +0100
Message-ID: <20260303120416.62580-1-david@kernel.org>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: david@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VPyUuNMv;       spf=pass
 (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=david@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "David Hildenbrand (Arm)" <david@kernel.org>
Reply-To: "David Hildenbrand (Arm)" <david@kernel.org>
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
X-Rspamd-Queue-Id: B73C11EEEF6
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC7JHAFRQMIRBSM4TPGQMGQEWOR53UI];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[googlegroups.com,vger.kernel.org,kernel.org,linux-foundation.org,gmail.com,google.com,arm.com,lwn.net,linuxfoundation.org];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[david@kernel.org];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[arm.com:email,googlegroups.com:dkim,googlegroups.com:email,linux-foundation.org:email,lwn.net:email,mail-qv1-xf3e.google.com:rdns,mail-qv1-xf3e.google.com:helo]
X-Rspamd-Action: no action

We have only the SLUB implementation left in the kernel (referred to
as "slab"). Therefore, there is nothing special regarding KASAN modes
when it comes to the slab allocator anymore.

Drop the stale comment regarding differing SLUB vs. SLAB support.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Jonathan Corbet <corbet@lwn.net>
Cc: Shuah Khan <skhan@linuxfoundation.org>
Cc: Vlastimil Babka <vbabka@kernel.org>
Signed-off-by: David Hildenbrand (Arm) <david@kernel.org>
---
 Documentation/dev-tools/kasan.rst | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a034700da7c4..4968b2aa60c8 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -75,9 +75,6 @@ Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack memory.
 Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vmalloc
 memory.
 
-For slab, both software KASAN modes support SLUB and SLAB allocators, while
-Hardware Tag-Based KASAN only supports SLUB.
-
 Usage
 -----
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303120416.62580-1-david%40kernel.org.
