Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBPQ2KBAMGQENARHFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 293E5341FC9
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:10 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id r14sf11891560vsn.23
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164869; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJ7qeKnqmI5lzClyEYIljIp8J0emzvmz8okdZVIYNbxTK3XoCmTiDlFwxTDfaUeuRX
         jwgMa6WzRJQErh6LUgOuIm14LsKE1H2I10DriQI9yXEofUZOCbZXlTzR90r+1/fYjvB1
         mbljfyw8T6C08XBtR32RgTA9hn9Ial++8sXH0vGRJ2GWvS19RGs8aydslqgxOCnAnL/w
         NeihseFf+AE0m+kQ2uZtOJ9npfBgQnzxkehyfQSuBMqsyw9gaLvwXIdpTqTtwYPBwqXM
         PsOBOEhwWl1PsUXrsLvD6xvIY93klOqHmN3JcRzZpc/SKwroTWl4KwBlgAeL/ZbL6rVq
         q4YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YgVtjh3TBgQzg9/PQKqNDvXKbCfS62czU/T53vzaXGg=;
        b=kY/MJZKO5lSq5nbvmNpDe1XsBnWS2Kmnr/GYO/y3ydOjsd+Y0zg3zmIAstOuejF5i1
         1uwwWofcAWBeYNIoxkcbmlk9VwK+cYr+fu8oyyKlKK1vOTu+0hNABG+EbvcLXOPxzOS/
         ZL+qICurRbwTlSPTkm3FMxu6e/2r/6fYKUfTgnlC4PFsd2xEmoCawVQaUEwEx+FK9y2I
         VA/EEnZWk4DmyN8Hl0OQr4YvwukHqG7PB7TYDCTIuUBEPpwnho67DjtLaEyJ9/xvRYTD
         y3C93M7mp2b5CedvhDyvsWHOgG4u/qK0lEbI+gaAp8L9JNhAjO1NTHdBQryZK3eE0dPb
         vP0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CWsyw4mB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YgVtjh3TBgQzg9/PQKqNDvXKbCfS62czU/T53vzaXGg=;
        b=qIot60d7PvBejqpMtDkNHbHRft/fNYLLPMPQ57QE5YFbadkQDO0qVDuTwaLLQI4/v1
         pngm+usX1KupHpdLHuOx92FAmV59qakXIWIL/Ftc9pViPIFGAoAevhS4wLujttCO1God
         kol+NPQgE268MOTnXTtWAO4RTEWT8MnNrw1UCyNGkL825KfSdHWBpUmqMMVu9Jsto3n9
         MeXMUzy9nJjG84zKMP21DUU0+n9BclUQjNXXfioCsjYloK9HE/UQa2B/jZNtMSb5YZ7a
         t0zNPgxzHXmZ/GHEj1UNUjH4CAWv68bgcIIvJaGqu5pixb0nbW4gyD5dzhnqRQ5SJNqh
         Jwrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YgVtjh3TBgQzg9/PQKqNDvXKbCfS62czU/T53vzaXGg=;
        b=dupbsZLX3OYX9tCBpRKsq4jOJMU3oAaaciOw+NJRgGIzYZIhLLEsyuBBm9uTx6Ah/Y
         fWwvP1LYJCSMlE0QXVWMDYyCEMLkP6aNpcN+aSsqZvuQMWRpRYTZxViHoII8BwRM+lls
         liXtPHd9q23vcq+7rcjHywSCaFzEuue7PibHvvMBKhwJO3OdWpz8fftNVA+iNI9powJm
         NECcssrxTCpPDJgnqZzsfPBjpnEoA2pOcfqgo2qv4jjE1uKjeUV3cON79NYlveOJ5Bnl
         wlQbASmM9zsFOaLhLAxmIlDIoKqRav5635svrOJ28VvQD9UYQ8yi93z033HxdRwRMO9g
         vJnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532O/IBPFLsvDD7S129WthWJW6NxIwTb30p326mD94/M0uu25VTR
	zfhBUBhe6ICgx884J/BR5SU=
X-Google-Smtp-Source: ABdhPJzhAI87Ucq78XZJsPomTHNuq6eBBznym4xbnTMi6m0CR72nfcb5Mw6m4MQQw6Q3qefWmWfUog==
X-Received: by 2002:ab0:74d5:: with SMTP id f21mr5490123uaq.94.1616164869199;
        Fri, 19 Mar 2021 07:41:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:475b:: with SMTP id i27ls425413uac.7.gmail; Fri, 19 Mar
 2021 07:41:08 -0700 (PDT)
X-Received: by 2002:ab0:70d3:: with SMTP id r19mr5605591ual.137.1616164868688;
        Fri, 19 Mar 2021 07:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164868; cv=none;
        d=google.com; s=arc-20160816;
        b=sK/0V7spXK3TRwrJFjrVu7YmmPdyasaHwoxdtma2San5Z/Cs8Rw4FgUt/SE/R9NHXD
         c2JT8PMKbXVqCOClRM1PEYtIf35/JQBbnmW9EV7KxiFma5GIP9lcgtbleXwRiA9MmW69
         xiCn4rJGGePcowEIyG51tR9eJHDQhX7GfARZx5Xh/TUHovTGEMgViTQFAB5Adim3mfuE
         Rvp3TWLGMRmmcf+NSjocK8vuy4kqmqBhytB5ApmrHmg19rUkC/N6aOmE7Tg3Wq9h7/gR
         EIHdpGVqSalpu+zIIvZAzkIoZZoJbuuMKA0UUPGUqXNyrtrsVCIvcH1kugQbNdBh+fkv
         wyPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ydwegfj06jUtcG1bKMw1Rb3csKPSe8+eJN43gEYqDtE=;
        b=EVlCAAkwofKxqb2/PrF8y5l6B4UOAcTr+zNhdjGTvutfXfa2S6Ic7+vvXb1mre39E6
         4IBVmTLyk1F+XF9sXDEHl8RKSBYv6uR/kYuwYhnRUogvcER0uJcfpxlQPM6Lc6dkmnuW
         ATkeVilqMLzt9hRduytFijRFO4wzZ280wkiT8cyh5uMTe57SLhuUmcVq6B7hRXSg9w58
         K2pSU/6340uWzl6eOxwq4d2BTAauvzx3m08QI9lPDlrub8JDRIN6rSHhh/Ib7x8S/sZ5
         3p8MJ9Hm7gqCGM6oiRNogpgR3fHDwOyXtADcY/dd3PqnN6ORkxXmLAmaJcehwYD602ZJ
         thwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CWsyw4mB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id r5si257901vka.3.2021.03.19.07.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id g15so6043891pfq.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:08 -0700 (PDT)
X-Received: by 2002:a63:181c:: with SMTP id y28mr11211891pgl.175.1616164868280;
        Fri, 19 Mar 2021 07:41:08 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id v13sm5242767pfu.54.2021.03.19.07.41.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:08 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v11 1/6] kasan: allow an architecture to disable inline instrumentation
Date: Sat, 20 Mar 2021 01:40:53 +1100
Message-Id: <20210319144058.772525-2-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=CWsyw4mB;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as
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

We also disable stack instrumentation in this case as it does things that
are functionally equivalent to inline instrumentation, namely adding
code that touches the shadow directly without going through a C helper.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..7e237dbb6df3 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_DISABLE_KASAN_INLINE
+	def_bool n
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -130,6 +133,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -142,6 +146,7 @@ config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default y if CC_IS_GCC
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
@@ -154,6 +159,9 @@ config KASAN_STACK
 	  but clang users can still enable it for builds without
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
+	  If the architecture disables inline instrumentation, this is
+	  also disabled as it adds inline-style instrumentation that
+	  is run unconditionally.
 
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-2-dja%40axtens.net.
