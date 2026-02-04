Return-Path: <kasan-dev+bncBAABBTFXR3GAMGQEFGH4EXI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aDAZJs6bg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBTFXR3GAMGQEFGH4EXI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:42 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 35736EC04C
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:42 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47ee056e5cfsf3156155e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232781; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kg8K3Ee9zvmUqTbmBHCuus4NnwUHKxD9+5OatgbqGzY/Ok02KoYJ1rJbsFXNsi7CLS
         E3oJQBXJPetSKWWDS8zdBXfNemDPXjS9quTwgQX/ePLIf+jwcIV0qusoHCJwqffRpauC
         qxHZd5OQM1S8t6MqkweFSYlS7Jkf+x60MZAfLxl25OCjNrjtCzH4jeoQ88bbKxRcHteI
         AoHcerYDHfTrTgiKosl6cfG33jvv/cwpMNSwPQAiSzB2AQxThF0EuF+wt0lcp4TLnB9v
         hLktf50lUB3AwVnT2I+n1g/wdOHsOpAgzmtPXD+zOLyE15olNvuf+pzJisJYiAkZ+BSC
         3AVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=L6wV3UAIwpO+WOT55VlMGK2liDWA/rcu7U8dpHuga7I=;
        fh=CTNWszhD91d2PAMngNyzKa/svQlJtgg1gtHpwWCbnQY=;
        b=bpB01bCSXWWt3eDitUDN0t13tukVFlcZGPfG6gzIpPz42vCVqYq030wJ21OXQOPoEB
         1EjLFEEB/z25gc5kMhwL9igz+Bvn55oLLbYRXjFGBO9oaFLsxPq2VG6bQPuJ3movcCE8
         GBIVS3lInfYsDUAO8gbE6v4L8dasC8mOasXUHLThg0AgsoUy87TEwp8P1Qra++EnMQwR
         p4zASL/ZrpUt7A//YdRznbHm0lMbAULE/09JtoMzkDc9uUu/vBKZhhomPm7nBDvMRPBp
         Rl4H0iNCVO0yg8HBHOiWP+DrrP+bksa0EZMHASpNgLt4tLj+s2kgClJW091FkG4NbNjP
         jxhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q376kZR8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232781; x=1770837581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=L6wV3UAIwpO+WOT55VlMGK2liDWA/rcu7U8dpHuga7I=;
        b=c0RGi/7Yz0j6AnqcW3avIfGaxQBE2UVZ1z4/J7J0+ru/XLHYlW+3mQr4FVLWCRvxXU
         FKEx4O9z2WtI6Z4jW5DF1/OeoHdktv5ECa0u9snH2uTLubPxMFg04y8EVvKH7ZeQw5e7
         NDcc7BpMSoWO2slSSgy/3B3Jpy+lMjimxIAcTenowmAxRt95SZI6aUfYZ4dDP9Q9OZOP
         JkYH5SsH/Hcf0+5VZcwPAtucZqQTjyEGWQPzRsCFRpNatThnRO40bmyjfkHSMO2mGMyc
         dfnDZOrkuNIItwYJ8zVOYFp/sjlw29ndo3EOXw16mA1q+Lbo8xM6c561buLV7F6cNFtt
         S9Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232781; x=1770837581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L6wV3UAIwpO+WOT55VlMGK2liDWA/rcu7U8dpHuga7I=;
        b=oPKtjQnVr3CvdFRMEFcCHUOlBT+hZd2laCCOOF6zl10MH+RFhPud0ecCHUPkc7WIn9
         X8y5vI/pvr+K6WvWGHAGmxDFe1g5Tu4Z7Er7VoYoM7LoHejEVvOv3CrvGZM2gEJIElYP
         eYgY1uucWqhqILvtQlHLwJNwrXsUeciYDFVQzBEZaQgjorIx3JsylmCNhMug+KsxhYTp
         jeiYzIE78HKyqQY4Ra5UW6RWOcslmGNRTU8Ry05punU9UQ9XrY1qEIy6SAEF69VsHExE
         peKmEssQPD1BQrkGlXNM1nDkKEPjWJNfhBx7e83VXUb5qLa2UWv7So+UfCrHwOY5LtT5
         mIRQ==
X-Forwarded-Encrypted: i=2; AJvYcCU4/SAGVC//+fl9X0uCYJ3ia6Edr/wh94zAq48UUKfI/myFn7h/1N3rJjXnC1UelV3gMky2+g==@lfdr.de
X-Gm-Message-State: AOJu0YxmuW2ktbhgfzTcde3l8kA0oUYGdapxPRt5kPWMOgezkl+A1Ht2
	lGn9lRaunw3R5QNEY9c+SS0jlHwS2mgSxWcMi9lXuE5oz/6ToERFIIqX
X-Received: by 2002:a05:600c:64cf:b0:475:da1a:53f9 with SMTP id 5b1f17b1804b1-4830e94d4f2mr50578935e9.14.1770232781219;
        Wed, 04 Feb 2026 11:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HXYhcwT/FFaCSoEGRh9qE9dc+awjVOukN5R1fCa2EIcg=="
Received: by 2002:a05:600c:1c01:b0:480:6dfa:4178 with SMTP id
 5b1f17b1804b1-48317598b8als1130065e9.2.-pod-prod-03-eu; Wed, 04 Feb 2026
 11:19:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVvJykhC25usteZMXzM5SH9yw/jKIkvkJNdSSJ0CsWMhVaQqaxci2addmDjRTXXng0obRf/q2DLwE8=@googlegroups.com
X-Received: by 2002:a05:600c:468b:b0:47e:e2ec:9947 with SMTP id 5b1f17b1804b1-4830e99d4cfmr55011975e9.33.1770232779567;
        Wed, 04 Feb 2026 11:19:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232779; cv=none;
        d=google.com; s=arc-20240605;
        b=EUtn0rmm8WdVFRPhWPvwMzw7Pl68OpqnXzP0DhvGDK20SmQh1lut7+NSPK01Mgnfee
         JwpDl2BrjixDM8n86SkQBfXyBk8SxFeHbHiq3kv80jDz91zbn+2HexzI+Uq2W1A0s/J3
         7E037iti+il4nUBwZdeehN4AcewTqQHr/gCaat33YG6Xmryws7f3PzJraTSKcmBlF8iq
         1mYDUgLJjIA4TGx3iKuyGmAvx8tc9UaNlF00sPqoiOYGeIf90aO9m1H52rDEOjvBsYYx
         BiWatTJXxNIi2oy12AlNzO9odgGnXejRx1i3sh+mj3BIxd21MGzt98xYfZx4HjID3sp7
         Zh0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=xt/M6F0af0Aewj/HTy9bWBamZzfKiE3bbOG01o2uFtM=;
        fh=cJFRJAATeg/CzR8znQhyPKClal+KVdtfWdbjznT5Qz4=;
        b=PLUENw5LD8++BAAIrW1wA6eBIbwoG1H5apOFAhfGNOpNiKcS3wVHDtaW0OMjjCPcbn
         yos1/ufLPgGlcJlZFQXXpzjUA6/EbdNl7mGblRACP1LJ/INDVeDIl4MgwFtfxA85oqNc
         0pNZN0yPyjMGd17HLeJ2FxGZ+ZrgFLizF1RTmiA6N5XDwCSMKrPksoL2PboXSy0LdC04
         8rH0gdUe64hRLPR/KXcJ8YHjpjv+F6sZjEAOdRzmVVtB3jXFrHN9PnYWVdc0yWbo8qmE
         3dSeJZ+zUoaxUDkiSBX8h0x2yKXZamwAGMl/rK7JaKL4/r4OqbPWMOVXI9fGIk3NgDV8
         9Oww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q376kZR8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4830ec0fd04si387955e9.0.2026.02.04.11.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:19:39 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Wed, 04 Feb 2026 19:19:34 +0000
To: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nsc@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: [PATCH v10 03/13] kasan: Fix inline mode for x86 tag-based mode
Message-ID: <2ee8abb956de90ce843a3fb7b971377887fe7a79.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 4be30621188735452b609f7e3a4c7ebd98176383
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Q376kZR8;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBTFXR3GAMGQEFGH4EXI];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,google.com,arm.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,intel.com:email,mail-wm1-x33a.google.com:helo,mail-wm1-x33a.google.com:rdns]
X-Rspamd-Queue-Id: 35736EC04C
X-Rspamd-Action: no action

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
Changelog v9:
- Add Andrey Ryabinin's Reviewed-by tag.

Changelog v7:
- Add Alexander's Reviewed-by tag.

Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 0ba2aac3b8dc..e485814df3e9 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2ee8abb956de90ce843a3fb7b971377887fe7a79.1770232424.git.m.wieczorretman%40pm.me.
