Return-Path: <kasan-dev+bncBAABBSNXR3GAMGQEARMOARY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2OT3Dsubg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBSNXR3GAMGQEARMOARY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:39 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9503FEC044
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:38 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b8749dd495dsf9119566b.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:19:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232778; cv=pass;
        d=google.com; s=arc-20240605;
        b=UsWdlWeCl9mYxkbjfa1GSV+4s/CIMqfDTgDtpd0mN6/LHhpaNhDgJMpIEJtbK3s3lX
         n7oBSE1+rBMZnfnaWC2ekeOTXDToK7g/G2XhBF826NnvHcQqYWletAFypk4D/1h9baG9
         StTFrZuyPTJFid+VGaLrSVa9WbJWUvpqRT1hrJT/GZRfRN454qTT5PUm1TfH+hT8rwXu
         bw8QdoWlR0Oa0ZndrYuza/I14gOKhisnSu6mvkkQbNwWgwTGAj25/IQj/rxpZIVnkdXd
         eGWgJky+rx9LxhZ/sMCJ0D9yMPp8ZyzPM/CE04cTF0Dut0gbN39tC5xio4qvsTWcDVts
         hIWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=Lc+GHfB/0yG9hnnIhV4Wg8LJlu+Fntl0s1KzrnB1vGM=;
        fh=butL3GK2XzkTthjzjp9kvelmzVAe4aoFnn3EDSvPF2Q=;
        b=LTSu0sGr5olGY0ujNau17iEYgFKWEWAoKTicrCGk6Fbyna8DUltmlGm69DrzEIxlXl
         qqF541yPpTUxnbdb8NNb8TfKo7je+dNoYpHCKZygK2rH3/xGsStWIyRp5nqV3MEW0xV1
         AXF6n+9I/fkpzMLJpbFcDHb1WcN+8BoQMpltP3uhJ8+qHyAKikRVyO/9CWynDIha9+aA
         RUTdcGjpRLLQDrL38IxY/oyVgl227Yu/O2EeEVaI6Ku79YldfsgOcD018beOjsMdzPYi
         vxDyAwedPbwfz+gLTH5NJu9x8OPXo84z60CMSTmaek3CelEaAsndRDB83dO7t0emV7mx
         p7Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="Hg+7dYS/";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232778; x=1770837578; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=Lc+GHfB/0yG9hnnIhV4Wg8LJlu+Fntl0s1KzrnB1vGM=;
        b=meEhQX7qWoie6/2axR45Ng05/CWeucAdgfW0MRJ3kjK02T0CPPJ0uMASnUdEn79x3F
         v7IDxIVcO5Ya3/XvaPtniO4OU6KME/aIdCDQ3bWMeZ+EXjALxMPXp/2C+vd0DXRET6Vn
         9FtMI3fbfyhlXpHfnY0fh9Dn2ZQ12eD6Obp67yj8/+SDDkmS7m1EjfmVgFElh09ImDTx
         hpef/wCstNgSzxdhcEaAZwAHvSq7j7JTZtOrJIOU1OuMEbKxq7oDRWGkY1T3Gn3prba1
         0++SaK/ol7jCNO5fDT5dFY3eZC6pMkndrjbjdH8TAueTnk/b1slZSYMQzQt8LWcPxWwT
         AOBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232778; x=1770837578;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Lc+GHfB/0yG9hnnIhV4Wg8LJlu+Fntl0s1KzrnB1vGM=;
        b=FJUS3jgnN/cH6/95pvcrpowK0VKI9odj6BJOlqaeeuWZBP9lty+RCWkHk3jASJ01ks
         8UX8I2TwF03fzKZZdr4UOQGm9u2AuL339WZBDJQ0as9QSJIVqXodUaGZihsURTvKkbQI
         X9Pjjetb0h07/PQyj7nhMz0suoIGQaZSW2noqtwvLqx5eQ3oabRVfNsgIvNQgQJWikQY
         ft6JZIPorxg4E67aTRKuAFUR5KU+kIyrwR9WqAmC4Qj69lvV+MdaB25tf0ONuol8saql
         M9JMzrN+v6c6V/t4xR5h7AiRQsZWmIs6F6eFrQSshJSmXGPvlvfBkgLNmEUMn3kfgdYW
         kR8Q==
X-Forwarded-Encrypted: i=2; AJvYcCVqTa/sE9EPEOz/zAMiWxg6sktZjA5ZHs4MmeLrCIg/viHGEzUKTRSUVjoFO94F3EPxZ9c1zw==@lfdr.de
X-Gm-Message-State: AOJu0YxqjdkFJVgI9X/62FHlEJ41AEnR7u7F2Ir3ErPkn30kJHy5DNgQ
	ccGk3IRmfPDtdm9T9TeMX3skL1BFYrYXRPlWhBjwPXWVbfwBWD7xs8zt
X-Received: by 2002:a17:907:80d:b0:b83:b7c5:de2c with SMTP id a640c23a62f3a-b8e9ef30b50mr312353966b.10.1770232777742;
        Wed, 04 Feb 2026 11:19:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EgxeT3PJF9VXGg1Icxiag66K0O6D8mCkQDWUqcA9yoNQ=="
Received: by 2002:a05:6402:3045:20b0:641:6168:4680 with SMTP id
 4fb4d7f45d1cf-659621f64fbls114841a12.0.-pod-prod-02-eu; Wed, 04 Feb 2026
 11:19:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVKi6b/NPT4lOEV8NU8kUIogebPfQPJ2EvLBMLrvIctt10CWsPi98ZxjrGNjlJTe2lIXdFkfmyiDTw=@googlegroups.com
X-Received: by 2002:a17:907:7b9d:b0:b83:15cb:d4cf with SMTP id a640c23a62f3a-b8e9f0e9e4fmr232684666b.29.1770232775891;
        Wed, 04 Feb 2026 11:19:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232775; cv=none;
        d=google.com; s=arc-20240605;
        b=lqN1p4VVl/6K21NURaS+n/gHrL4CJudfJnEXZPLpdP5kR0P42V8Ymv01Ipb0ikb2UE
         WWRecW4yL9M4zAI0eJEla4HH4JvPdhPT9TDlxs5P1cUqV1jKXYyknPuG+PdzF0TVwWOl
         J8Tln8s7GcW3bF431UXiAzt85Znj4/STS3ArdFW1dvcQlTo+YZRC9w0P3rzG/JzNgDSl
         loJqsX+gMwBXkPsUk6MaAEDJ0rekEkKlpUPpNChL/Jg1Odm1u+sfZYNP3dhr125ublnL
         TxaM2MkZC7ND3M6rI0Pt1NAXFZTZrEd69RjEOB7xV89XZr4+H1cwGFehSP2lu39liBdy
         sKeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=5O1b3FfR1Vp+0do34cNQaTZ7/jUxE68vpVVGzruC3Os=;
        fh=uZZjx8zNTRhDZ822FZcs1jFprs7O36SIqgpEkngJLy0=;
        b=VQeCuDKVdJsZRq7YYrqx7MFI6lrNsRHvI0ASo7mhtgzhAh3kpaJIXjCWEHNOEspBFE
         t+lvPv3zrWDgIqofzvnS8qVfU1Cc7NFEXrYY3AXp1u3pd9rZY1woQfsIxSbwLBMUtrNZ
         qcyHzDfsbA/WEJDk1L4/3c1PFTClX7QYinuiEJHDN8s1SiN5Bn1i+x+uELBPwlbxuObX
         rkSMbtJLbkC1+LXQSNtKzm1N0nga4YkCj4NPia0Ramtvsvb+/WPln6QJohugI3bMaXkN
         O4dpqefjrtguHH5aWk4M46g94uz4+6cd+XcUmrEEeZswLAiwBAvQna+rvfxtDeIRGikG
         FrWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="Hg+7dYS/";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106118.protonmail.ch (mail-106118.protonmail.ch. [79.135.106.118])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6594a0d1b3asi68209a12.0.2026.02.04.11.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:19:35 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) client-ip=79.135.106.118;
Date: Wed, 04 Feb 2026 19:19:27 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: [PATCH v10 02/13] kasan: arm64: x86: Make special tags arch specific
Message-ID: <2680630ab18d648422d3ce2775b76f8afa0d1e01.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: e73d08e0b0321a8680dcd736a6f57b61ed147d52
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="Hg+7dYS/";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as
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
	TAGGED_FROM(0.00)[bncBAABBSNXR3GAMGQEARMOARY];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,linux-foundation.org,oracle.com,suse.cz,suse.com];
	RCPT_COUNT_TWELVE(0.00)[28];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,googlegroups.com:email,googlegroups.com:dkim,pm.me:mid,pm.me:replyto,sifive.com:email]
X-Rspamd-Queue-Id: 9503FEC044
X-Rspamd-Action: no action

From: Samuel Holland <samuel.holland@sifive.com>

KASAN's tag-based mode defines multiple special tag values. They're
reserved for:
- Native kernel value. On arm64 it's 0xFF and it causes an early return
  in the tag checking function.
- Invalid value. 0xFE marks an area as freed / unallocated. It's also
  the value that is used to initialize regions of shadow memory.
- Min and max values. 0xFD is the highest value that can be randomly
  generated for a new tag. 0 is the minimal value with the exception of
  arm64's hardware mode where it is equal to 0xF0.

Metadata macro is also defined:
- Tag width equal to 8.

Tag-based mode on x86 is going to use 4 bit wide tags so all the above
values need to be changed accordingly.

Make tag width and native kernel tag arch specific for x86 and arm64.

Base the invalid tag value and the max value on the native kernel tag
since they follow the same pattern on both mentioned architectures.

Also generalize KASAN_SHADOW_INIT and 0xff used in various
page_kasan_tag* helpers.

Give KASAN_TAG_MIN the default value of zero, and move the special value
for hw_tags arm64 to its arch specific kasan-tags.h.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Will Deacon <will@kernel.org> (for the arm part)
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
Changelog v9:
- Add Andrey Ryabinin's Reviewed-by tag.
- Add Andrey Konovalov's Reviewed-by tag.

Changelog v8:
- Add Will's Acked-by tag.

Changelog v7:
- Reorder defines of arm64 tag width to prevent redefinition warnings.
- Remove KASAN_TAG_MASK so it's only defined in mmzone.h (Andrey
  Konovalov)
- Merge the 'support tag widths less than 8 bits' with this patch since
  they do similar things and overwrite each other. (Alexander)

Changelog v6:
- Add hardware tags KASAN_TAG_WIDTH value to the arm64 arch file.
- Keep KASAN_TAG_MASK in the mmzone.h.
- Remove ifndef from KASAN_SHADOW_INIT.

Changelog v5:
- Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
  mode case.

Changelog v4:
- Move KASAN_TAG_MASK to kasan-tags.h.

Changelog v2:
- Remove risc-v from the patch.

 MAINTAINERS                         |  2 +-
 arch/arm64/include/asm/kasan-tags.h | 14 ++++++++++++++
 arch/arm64/include/asm/kasan.h      |  2 --
 arch/arm64/include/asm/uaccess.h    |  1 +
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 19 ++++++++++++++-----
 include/linux/kasan.h               |  3 +--
 include/linux/mm.h                  |  6 +++---
 include/linux/page-flags-layout.h   |  9 +--------
 9 files changed, 44 insertions(+), 21 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index bbcb5bf5e2c6..e27bdb0f100d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13586,7 +13586,7 @@ L:	kasan-dev@googlegroups.com
 S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
-F:	arch/*/include/asm/*kasan.h
+F:	arch/*/include/asm/*kasan*.h
 F:	arch/*/mm/kasan*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..259952677443
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
+#define KASAN_TAG_WIDTH		4
+#else
+#define KASAN_TAG_WIDTH		8
+#endif
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index 42d8e3092835..ad10931ddae7 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,6 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 6490930deef8..ccd41a39e3a1 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..68ba385bc75c
--- /dev/null
+++ b/arch/x86/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		4
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index 4f85f562512c..ad5c11950233 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,22 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#include <asm/kasan-tags.h>
+#endif
+
+#ifndef KASAN_TAG_WIDTH
+#define KASAN_TAG_WIDTH		0
+#endif
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 81c83dcfcebe..c6febd1362e8 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,8 +40,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-/* This matches KASAN_TAG_INVALID. */
-#define KASAN_SHADOW_INIT 0xFE
+#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
diff --git a/include/linux/mm.h b/include/linux/mm.h
index f0d5be9dc736..e424e68569a2 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1953,7 +1953,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags.f >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1966,7 +1966,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags.f);
 	do {
 		flags = old_flags;
@@ -1985,7 +1985,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 760006b1c480..b2cc4cb870e0 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -3,6 +3,7 @@
 #define PAGE_FLAGS_LAYOUT_H
 
 #include <linux/numa.h>
+#include <linux/kasan-tags.h>
 #include <generated/bounds.h>
 
 /*
@@ -72,14 +73,6 @@
 #define NODE_NOT_IN_PAGE_FLAGS	1
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_TAG_WIDTH 8
-#elif defined(CONFIG_KASAN_HW_TAGS)
-#define KASAN_TAG_WIDTH 4
-#else
-#define KASAN_TAG_WIDTH 0
-#endif
-
 #ifdef CONFIG_NUMA_BALANCING
 #define LAST__PID_SHIFT 8
 #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
-- 
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2680630ab18d648422d3ce2775b76f8afa0d1e01.1770232424.git.m.wieczorretman%40pm.me.
