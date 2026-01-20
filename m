Return-Path: <kasan-dev+bncBAABBFVIX3FQMGQER4VLROY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UPXSKKWjb2n0DgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBFVIX3FQMGQER4VLROY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:47:49 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46BDC46A9A
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:47:49 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-b801784f406sf579412866b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:47:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768924069; cv=pass;
        d=google.com; s=arc-20240605;
        b=KNP52LRs4rujCyD8lPI6oJMC9kMcZau62a7nOu2wonqhiVDEjAreexBnj97reOgYzq
         QO26H0sTydizrEYglC8rp7jsJU3UOOebpAYF6RvU3L88FA3mVx3Wm/YFo0wQkspLLKQb
         zwrEBZOe05f92ostGpMd2b/70OR+YzG2FX5TMyOylzFv3eZL3DkqySE+BD3ZlH++YlyV
         Kyp0LqIXI2CEvqBocxLZypeue8OYR3QLyIaXaOqhgPXleZ+NecpFcz8+5SFIVtDRESqf
         g0yFr70JszMzS44k0x7JxEwAZKIH2Go+kJ7TjZjM0Ynaz9yqyATXU9bZzRpBN+TW5DmD
         6Veg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=d9Ie3H17DLFcz75BqJe92YWZTRhhBKhLgEryJKNSWtc=;
        fh=6rHTpz9lT4yYxcsz1PWkzzNhpjVXjr2okTN1y7S01NM=;
        b=AwWHD88lz/XbBUd9kw0XRF57RpY6tLH1DDsFl10xac2Tea5MUgnbcgxcR/JnBkomyU
         kEIzwVejIRtW7jVYRlpmfFZql60sUeVcmNFStLJ2r6ZZPvyRzUePCsqVCc5rCmzhgY37
         HwUUGVGy/SN1Y10gwZHbiC4ud5vr2+3VAFsSrZz7aN6qlhhWKcigZCgmP9XP0LTRawrX
         hS9Sd3rPCZpNIzmwSNQdOxBrQNLU2JMbKfOmdfoK9Xxk6kHR7Wc7xZlBnL9x0vRm4G/v
         JmBo/JxZ5OFgRJk79Yp50vMwtMrhAqm4uP/QpC0ct66hmf2csa4ciDHEAoXhOMbzL9DB
         iEJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=fIMBnXKN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924069; x=1769528869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=d9Ie3H17DLFcz75BqJe92YWZTRhhBKhLgEryJKNSWtc=;
        b=fO0exjwGZMuaQwsI3+G8AWbzAJzShCNVLdErho4Juj1AioBe4XQqNbO4/Fr9MZICpS
         PFLWTDzwHPcaBlmgiJqzZqio6cK/+AA3BbYd+gXeWLYxk81c43wOmoNxTZcZWA+SQaPu
         kyU4DhOASMCzwvQ1EC3m/vm8d9liLbkRKJsNFamRs5KYgv7rVWjY9UQJ94n7U6Av91YT
         tsnkNdYRQxo1bRG/u/RNlJ1mbRVOQoPaWGXeEulfzPju4V3LApk9O1Hap6YZwi6zjNFj
         KxU6FDpFfrcyvhnWw/kme/oi2rNSQKKb8Kvaq9BwPbQbql4pSfCy1s1DXvuoAXnCSI8S
         h4Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924069; x=1769528869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d9Ie3H17DLFcz75BqJe92YWZTRhhBKhLgEryJKNSWtc=;
        b=mMPvzIHYVZ6AHcDbma/E4smExmx9U1xs2GvDXKJzooZR/rSUQVR/II+jlqPUD+bKDd
         DWmZeGaaPq8TmtXm5wamOyTwfqeym2KN6PBS3Fiatbh8I9Ud0uuNN0E/DYO4eJNUrNPT
         Wn5hiHl3MJ0VNV9ax9PDm6kK+SYLPalyBpZ/bURyks+Hn6M+hWpbv3Zq+ckbiTkb8NU0
         9KUU5k1MF+OaGPCi4o5TKwDgT6l2cN8sq/5S+Jah9Q0kSAuIBI2ULONlPk/74EbDQLw0
         5zyzVcKN6syMj0p9cIGWUKmDffvad9RGMwW/8QmopRw5MJ3XXJqIBu4vJpCtE/h9Zb3y
         Worg==
X-Forwarded-Encrypted: i=2; AJvYcCV84+yruYmFRnRUoZaLPVBJkg9voqQgMZRHt5/KuE9rUl79H0uNorMBgH/EqYgsxsBVVOkXjg==@lfdr.de
X-Gm-Message-State: AOJu0YyCSIRLJbsIp/kNP0oXtcj9aZLriML+RsLVrXA0FffIh9N7U3ps
	+u1Cx7i1aIZupOA6k9Vf+UwUgnTCNxM8EBIpAAETJkM7MvkQMefxeT6t
X-Received: by 2002:a05:6512:3e18:b0:59c:a027:b168 with SMTP id 2adb3069b0e04-59ca027b457mr3545137e87.30.1768920087628;
        Tue, 20 Jan 2026 06:41:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GzNe6WExI3jnwFNdE4ng48Lrv0ocWTFHWuebymBuEZ/g=="
Received: by 2002:a05:6512:31d2:b0:59b:6d6e:9887 with SMTP id
 2adb3069b0e04-59ba6e4edcels1806910e87.0.-pod-prod-02-eu; Tue, 20 Jan 2026
 06:41:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUk5ZV8v+n3IJMgKAHkOxM5tc3x8owJHx3kZ4+As5BYjbPkPHW0W+qKJwxy5nY4ScOY5Fw01AK+09U=@googlegroups.com
X-Received: by 2002:a05:6512:224d:b0:59a:1357:e449 with SMTP id 2adb3069b0e04-59baef002d8mr4996414e87.42.1768920085577;
        Tue, 20 Jan 2026 06:41:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920085; cv=none;
        d=google.com; s=arc-20240605;
        b=C71meUkCjKiSKSrXAliAGTrjOsca2bHL+2eb3QavyJLypiQxLK8gAjmw6MU9CKtYre
         5DT4Q/5NOJ6lejImUbpZ5ik3pnUNibjrwaT2E2zQpY53u6ufuuFgB9zNwWPGfff8qDCb
         5873jdi6RXi4qCDdQk9eEOyo4PGoeYAelw0Kqwb+VKvdvc8bGsJguhHmT1OcW/d7nXLT
         9qxEitiraq5RZk+WQM5xBpN9xwDTw00wMkjiyyPHz3If7/0KAzz+KGtOA2Yjbxn7EPxs
         zdE0OlM4leNb/VOmUsOJq9HBreJGqmXb8TL5P38miWe5vvs/Lp+vEDPWxwUjjSynGjEZ
         rGHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=9hxw38OLLXdn+9VGuKWdisEOvAzjfmeUi2K/qt7IE/4=;
        fh=bhd4K9Ei+4+mc6Gi4MZRIY5mLVB/mdiXpXAowoqb4hU=;
        b=Q6ctp3JlYma6AwWCsKzP1moDzHIRGa/kHDW/2GaDcgy1EGsDbA9yIzXXjNgpB45B8+
         H92tkJGVSnnF+PCHqhGRvKxGYDDkotVU5NpFfqS4rrI+cJNN2TBIPw7GmLu2c+aJdUUZ
         e2Ff7NLv0sDRbZP3AoYdJXVgrZYi+fYON7RvmkZ/5PEHoE+lPBfCX7sdZVeJzT5g791C
         lsKXfbLx6er1H8o9n4pjH58Q/YpYAIefXnqC656tXqEXiQaDeOrO75nnjPnmj8rHPBdX
         xXhxwCi1Uvw+9nJWSnbwOytcT1qDENxZBjJ7BXDpa7kUC618DfWfErDygOfUHBfCT65d
         U2lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=fIMBnXKN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43102.protonmail.ch (mail-43102.protonmail.ch. [185.70.43.102])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf393418si227658e87.5.2026.01.20.06.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:41:25 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) client-ip=185.70.43.102;
Date: Tue, 20 Jan 2026 14:41:19 +0000
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: [PATCH v9 02/13] kasan: arm64: x86: Make special tags arch specific
Message-ID: <2053362955d8b719b25d962c0bb1c5e56888f495.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ba4fa83822e36fe09ee7010abe018ce1287ac7fe
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=fIMBnXKN;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[arm.com,kernel.org,gmail.com,google.com,redhat.com,alien8.de,linux.intel.com,zytor.com,linux-foundation.org,oracle.com,suse.cz,suse.com];
	RCPT_COUNT_TWELVE(0.00)[28];
	TAGGED_FROM(0.00)[bncBAABBFVIX3FQMGQER4VLROY];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:mid,pm.me:replyto,intel.com:email,googlegroups.com:email,googlegroups.com:dkim,sifive.com:email]
X-Rspamd-Queue-Id: 46BDC46A9A
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

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
index 8e0e776b66a7..87c0f0e44f47 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13584,7 +13584,7 @@ L:	kasan-dev@googlegroups.com
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
index 0f65e88cc3f6..1c7acdb5f297 100644
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
index 6f959d8ca4b4..8ba91f38a794 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1949,7 +1949,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags.f >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1962,7 +1962,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags.f);
 	do {
 		flags = old_flags;
@@ -1981,7 +1981,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2053362955d8b719b25d962c0bb1c5e56888f495.1768845098.git.m.wieczorretman%40pm.me.
