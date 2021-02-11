Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7U4SWAQMGQEJCUOG3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CA8C318EB8
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:24 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id o3sf4284830pju.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057663; cv=pass;
        d=google.com; s=arc-20160816;
        b=fBk2BuPnK6Q+vJMpo+mQ04/HnTPfsbbvwfmbFk/DIU6SGxS+uJQt5Szq+lhq+iJbHN
         ZHSLwjEn9RAO071iz2fjvhZX6/oDTNjxPlzxfTE3XXYO4QEj122Fi2KeUbivGKYY1BC0
         3jyW9P20hsnAYp3709H14jnztSQ68uZ8XYaqkiS2hY0MfSwkqG8KEqp3lrgq+k2rUNYo
         lokNVanK+jztEcD3xcA3ST+eIqiQngcFfJq1XhWMkytdS2QphPgHRHT4o/N8zaLXdHc9
         /trFifdyc1UgqUehdJTOYd84z+jroSGqyzMBW+2nOOhnFclcioTxOli1BSAK9TiSvbiY
         AdQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vp2HG+kq3CkQ0WbeKSLUZ8bw21FZH/YB1xYrS6iy6+Q=;
        b=k2ok+354AFZxPqHcRvLcxsuB3RDLuWkLV4nikrcbAKGD9Fspi31sandViZ7cB3uIJE
         RHrUqpBOgSrCbN/moxo1uUpMZSpbhixLRa2PvgpVG7+aXjuP+CK3QlVRYhuGsBWa/zs8
         P/9iPCE9ZF11e3LD0nFLc7p++I6ZZ+0HU9UVvVhHSaVcHEsePip+sHMilXrd8m0RHjM2
         S6ryfnvZWhTtMx8PhrQ4+lhKG+E6tjUoHQ0ByQBOjv+xmCjCsT+ghg6bOg8kf+EpnSow
         G29yitU46aOd8EnysaBAx1nonwajypW95YdPfLdqeaOVQsUDyNOT5Ljzu2pJTkWlNReX
         CIug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vp2HG+kq3CkQ0WbeKSLUZ8bw21FZH/YB1xYrS6iy6+Q=;
        b=iM61qniJgJIr6Dlnk/gDPgQWzJTKatFOpAy+agf/A/9Yo9nwu80fgxYyV+WLzSrJGh
         en9mXEHCRXvWcBMRwWi2GrHVdGlssxxlsRgj1ib+K5O+QNTJtY4iyxJrhcZkXrCVb0tu
         xkTd6I3ywOzEmE4MOA9DgwTJrdx2tvAmUdwD2vtCEI4/pwumwPl3XItCxMh3RgZ7F7cD
         2SU58Sxec6TV3rMmnnA1tQ+k0PPsobTQTAAbmGhGYnD0SjjW0amGGSxxY766ykHpgnbO
         Q6hALXsAXH0Det2PxIygq+PgHhp58p8H1IY2C6mCvSmLnmLv/t5jggV8ByvRhKfz0/YF
         MlPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vp2HG+kq3CkQ0WbeKSLUZ8bw21FZH/YB1xYrS6iy6+Q=;
        b=HHKDvErd3utxumP/veOscfzvWL078zCwV1udbI6/SzLPcqGltve4CuF/3FZTu7hUOr
         /xHUsp0/CwE+QbcsenDuOqpb75NCxamjL7nmj1IIKXKMuyOAW745Mmool48rxkptvJGe
         cHJDqKxBR9UW8odezd/dN0MzWxrrL2ufQnnP4QxPfryZeYpwxc0i5dyRAkVpAMIs5+wU
         JuQF3kR88bQ97myO6REi2o4Q52Ai3FXZu4KYwhn1IxDSh+aiPs4yNuK9zCF8I8/pJrDd
         zALb9XDW3pZ+AYIAXDAS70uZaJlGJDwzxIiGe9vQnYfFWIujT6+wisWZzRWl4yxr4dcf
         ffdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eWkjp8gWuFzkJE8VLfw/TKNSeQ3TXjiNDEIaCNieGEG609NYH
	3EOWKfQgFJ+bSVD4YiWzKDk=
X-Google-Smtp-Source: ABdhPJyMxyZ3uaeWlAXNq7seG/NkqYLQp9dzGoMgRStfnDjygBbQArRfZiP9jb/kXQvWGAw93p9kqA==
X-Received: by 2002:a63:1723:: with SMTP id x35mr4073930pgl.393.1613057662544;
        Thu, 11 Feb 2021 07:34:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2c1:: with SMTP id n1ls2563348plc.11.gmail; Thu, 11
 Feb 2021 07:34:22 -0800 (PST)
X-Received: by 2002:a17:902:e844:b029:de:5abb:7df1 with SMTP id t4-20020a170902e844b02900de5abb7df1mr8237052plg.55.1613057661936;
        Thu, 11 Feb 2021 07:34:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057661; cv=none;
        d=google.com; s=arc-20160816;
        b=WRHKHNNiVNTT+l4p7YR2Y+ucxcQmZTNqkH49YNe6S6F+iOSptnCYXit5313r8Tw3Wr
         6xayfpkeab57fGY3AxiwC4Rwi6+FoMBFJ4fzhxJd2vBUgxtyo+iIkGX+7KMDa2Ot50/V
         mcsEbc9cDtunsg1TpUqX0G2hZBsNGgPF3zEL60KmV54NVB/40BG8T1tScqvNhn/b8XLK
         haJTpYeiUVmr4++box+RP1GnZhJyUQgJL1P2/L/cOfAHucrUK6qCsh53uMRvIAxq5vlY
         ebAVfe2Eti69WLQfAp55bWYKBmX0+pyLvvN1A+wAsaqyd6AULN+Qh+2N+OLALECa2bK+
         mf9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xju6JS+PiY4QcT8gJWQFvy81kwfZULDAPFGDpAGzM0w=;
        b=VH+FCLUGdLt/KD7Nli2fKIgU7fM7EGxjOvb46CT565cCoAy/uFxN2I4MraGKNSYMYw
         s+RO/SoiopTNa5OYtyiRhTlSGiUmXMxd+7cerw3wDOZS+0k5LIYtW42FLPMot41pmyJq
         oNYmrEIWY7F88H+AQDH9MI083mfV4hO7eehbcvANlcbUksm9Gio8BHh0uYIux/UH+6iq
         a1L4BLo+4/++elOR5BGw7W4hQUB/cNqAfyb8O0m2YDADPr3ylGvRRLQ+N6afE5z1LA8T
         hgis7UcB4GD8PWHGNhKxycfkl1IHK+zkXUfZ1Vi2BhbZE3s0z+nvHEna2YJgH1iMm2lN
         veJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y16si323067pfb.3.2021.02.11.07.34.21
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5BEBC143B;
	Thu, 11 Feb 2021 07:34:21 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 75B5F3F73D;
	Thu, 11 Feb 2021 07:34:19 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v13 7/7] kasan: don't run tests in async mode
Date: Thu, 11 Feb 2021 15:33:53 +0000
Message-Id: <20210211153353.29094-8-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

From: Andrey Konovalov <andreyknvl@google.com>

Asynchronous KASAN mode doesn't guarantee that a tag fault will be
detected immediately and causes tests to fail. Forbid running them
in asynchronous mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 lib/test_kasan.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index f8c72d3aed64..77a60592d350 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
 		kunit_err(test, "can't run KASAN tests with KASAN disabled");
 		return -1;
 	}
+	if (kasan_flag_async) {
+		kunit_err(test, "can't run KASAN tests in async mode");
+		return -1;
+	}
 
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-8-vincenzo.frascino%40arm.com.
