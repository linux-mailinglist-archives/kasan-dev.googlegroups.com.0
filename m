Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2OYTH7AKGQEIET2JOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED6E52CA7EB
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:42 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id x7sf1777626ion.12
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839402; cv=pass;
        d=google.com; s=arc-20160816;
        b=0wnisvs/YnTXGBvVpMTrVGviRQdvZs5XZX8w5BDtqtJz/ZoWYrg/P/iWeD84+RXF7r
         uDcXKCm4Km17IJsjBp2/MnTOBnOKOjEPpEVlJq73vQT4afsw/Y3TkPdREAR9j9AsSTd3
         iqIQHPiTAEUrzc783WUYjU+eF6DVSyUg//h6CoAUsXIkFIbWJD5HOzhhz4dD1Jsh3tq8
         b53mqOOB+fXmorcfB5fAcYuTq9ZLmYOwDt36ZFTAjfjkQetq/VHrdQIgVzEN58cznYFC
         esEp6LLdRH6gYgDw4XI1KPjL1utX7F25i9udBrb0pFndNy3cHueIF6C0rXLLDyhik9HA
         1Buw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gJwXUXHmjZIupVFHFCS9sy4auT47/gTohXKbJKDuZxE=;
        b=SN6B+b/acdRFDObVl5RQVoJ3WrXLpOFWxPJQbWs6xvoB6fDCBUhNJneacBomS/3FBL
         NgNBv50xHr+mvaUrPxII5Mm6wj9OPZbZyAduIvFNmkMgPLz3c2yyv7TwhADQncG/z1/K
         LHeBzaL5vBRhpNv6z0HyUXXz7HOsBkFgCidLYWKmcqSfe+aziHgSee1c48ityElOLYXR
         D1vtOMo8w1nJeuYALoS4PooHhJXsxHeDr6lQ5MjoPOT3JOgxWhzYYY1QDIvFzpL1GlkV
         suX/hYt0EvKsZW6d3t95P0UIDvyRlffkpzyj5hYmPNwLJ1uQlZoD2TLlI38xB3RYi/13
         3Oxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aaIMgn1k;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJwXUXHmjZIupVFHFCS9sy4auT47/gTohXKbJKDuZxE=;
        b=V69yXSZ4C6A4excJU6Ak+zUHRXi+8zpKJBodj0PIC9yDHm9mK4vH6jckoyc4KWV4Zf
         Q2D0wIsnxouGH3AQtR3BaR0OfwtT1Pa7bGy64NnFSZ0yMcplVlpG1o1HeFO3TTdYPqTp
         DU4ZSZHGgcRSS/m5WJ8JS6nYW7YqqnHDvX1FVof/INzw0qEJLsyHu5YnwrQtVsCNUYH/
         g9RFtOIDYGcUhiLW3YSSnVZFx8r6Hou01VopotK5QNLRwYKFPhUOQOjLGZsbtzrHi+VP
         WqUgsQ91ZuQRXPGgZut/uvzhTkuqnePkHx6ks+aHFZZyr0+Cbu96klcdLxQsWUkrf+gk
         rvoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJwXUXHmjZIupVFHFCS9sy4auT47/gTohXKbJKDuZxE=;
        b=Jwrd09YWALi46XSAgacD+7EKkos0txV2cADXXAd1R8TBsEYORiQB4PIR6X50+NrKFt
         1hyi72CB6GgkTBDeB1J1KlSBtafBsDLnLxnhF2csrMa+4PBfuASUvbXZAjePpR0P/5aX
         qM/btdHKKnPhnOHHsC5AfRC5vciTxI+wcQrVcjP7+4yThWzxUkAeZNdVedMUy7BhH2BY
         TEdgQwf+6T2pskimndDtG08FKlz7PD1YNFpeupceWL5v3LFJBrHhUCCit686jLPwJXBc
         XgZqgeRDMFgCahoLqk3k3G8YjbPz8dUDnu8ZaLcDGuAtvOa/QCvLG2mEDXvfaplXcWdX
         HG5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532f/MdhKLobKdLk430PNcmhcjwIJ1KjMXhxXM+Td0rHR0yzVupf
	sH+ZLALMOEYjYv7W/7x9gNo=
X-Google-Smtp-Source: ABdhPJx2HUFKPHT1joknfBpVyXf/BkDUkL5LI9pysXtSKFuoXa+vBd1nAuBVV6mmSIbKVbPp+v2Ixg==
X-Received: by 2002:a02:2b09:: with SMTP id h9mr3213624jaa.101.1606839402001;
        Tue, 01 Dec 2020 08:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:845d:: with SMTP id l90ls766403ild.5.gmail; Tue, 01 Dec
 2020 08:16:41 -0800 (PST)
X-Received: by 2002:a92:a309:: with SMTP id a9mr3390046ili.301.1606839401501;
        Tue, 01 Dec 2020 08:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839401; cv=none;
        d=google.com; s=arc-20160816;
        b=Qr3r+XlcbLDJJx/yVzA19RS+r1EfYG8oTXy//+Riyxipw2xiqmOn8wJ4bEp6XTx30h
         geNiHWayME31UvPHvXEgX11PYSQUCeF7+rZS1D79AhSlJkjA8Q2JuUH7EWMxFJjy5YRP
         kjKjf63GxApVSRG8VAVUXbVmyd8nZymX+7kvkFuq24FwIhY4cCnshJ40jZMF+TUxq2AD
         Y19VIXVofBCpdPEm4Q83InF2o9cRRy8JwV3mWFqt20+vWmZOdTylbGl1XnTB3L4xM5jM
         /sSUME5UNQF5sPuMEa6y7ebK296oUJJKh/S2GDonSmG2JueQnpegr3wPfZJFVAizYqmU
         kUMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=N0YdCjkJ51EOhZtuBaCrGJ/RvqotXRv8loSeq+0K1Lw=;
        b=tvN0xrLGDi50V0oApRsL8orbvrFkWanHsdmO7lU61QqcxX1HIkHUOLfRW08tb3qtkI
         cUZ2ele5t5si/KxkjiD73K6v5cdF7QEjXYtpZztoEHBvWbafLQgXPagsZuuugcUvyBOA
         S5y+26CbAWY10lWh6mPkuGUQzUW+vRTf7Ok7PtpeKO62YOxYh+xUQ2ReHn/R1DATDPyw
         qRRDFm1kou9v5N3yFeFltmlzU37cIhnKwrexjsyTLCH3mkS3pLeqOuFwK3LSY+5LksxY
         dK0zPPH9zNjGpELt1x87vbbpBIxR6tCvBToVROzJRuFUFzMOhRIwUx9ftv3vX9a4LcfE
         sYcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aaIMgn1k;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id m8si3799ilf.2.2020.12.01.08.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id r2so1414324pls.3
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:41 -0800 (PST)
X-Received: by 2002:a17:90a:a2e:: with SMTP id o43mr3337563pjo.59.1606839401186;
        Tue, 01 Dec 2020 08:16:41 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id q72sm222708pfq.62.2020.12.01.08.16.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:40 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 1/6] kasan: allow an architecture to disable inline instrumentation
Date: Wed,  2 Dec 2020 03:16:27 +1100
Message-Id: <20201201161632.1234753-2-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=aaIMgn1k;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

For annoying architectural reasons, it's very difficult to support inline
instrumentation on powerpc64.

Add a Kconfig flag to allow an arch to disable inline. (It's a bit
annoying to be 'backwards', but I'm not aware of any way to have
an arch force a symbol to be 'n', rather than 'y'.)

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 542a9c18398e..31a0b28f6c2b 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
 config	HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config HAVE_ARCH_NO_KASAN_INLINE
+	def_bool n
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -108,6 +111,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !HAVE_ARCH_NO_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-2-dja%40axtens.net.
