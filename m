Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGU3VKBAMGQEQKZPL2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 647FA337FB1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:31 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id a2sf10529324edx.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498651; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbIo72rAOsuXbAVqbqoRAxIh9AWoHl4pqz6dGIl8RM8FXVt462cLWIooQ1M8I/Fyde
         AnKKeaw5EmPYI26axO3sXbUUc3e8tmOc7PGVyHkdlweKlcxSXZ4+4rGSH6FxYoK9r0gt
         HJeSgUsS8lJypcSNlKwlBsgxbt7YwimZYqqLDTp5D0bAjoD7uVdy9zh2KKiHxpuV95O0
         78sBmfrg48Lx5tV5IRkn5twluvOSFETTQ9BM6L5ZRt++NJN5ZpGHwM0GFWm1WzQoxMqE
         yOIfFOOWDMLxBbKEadk7Dbr6L47yo9h3SYgHAOnNSPnDiiPlH4u1n/G/Ke6up+yI6lT3
         //lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Oi+caEFKpbeq987Z4g6YtXizFsBBxbMC/8lTdOUigOo=;
        b=PxOp0tfFFd6HHDdrCKIM3Cz3eOFl3rnopdPBJ3OYvIwssJmD9lrfzR7+oftjbQ35Aw
         fecA78tqc9qIm56buyU0rHXyZdjjHNLhR+ZY0iLMW87AKNCDJheus6HWCRSBTYo6efQO
         x5PAVhw4avFMGAgUM74CfqYreHvqJOa/UeeN3PNOrkl6K63cFkISrNyHQKklNIS6WTPi
         mdVYewHQFAd5ysQG8blKJZPVSrDPO/MnIhXlZ+PNDW2eDqVh9SW2fDwSlvgcUTp0EWhf
         YnZz6pj8/JfP/ynl6miv9HLSpvRLAPnycypuvE3IJvDa3ApOkYLfYxubtNjXTn35IfYe
         a1DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AN4kaYWM;
       spf=pass (google.com: domain of 3my1kyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mY1KYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oi+caEFKpbeq987Z4g6YtXizFsBBxbMC/8lTdOUigOo=;
        b=kxHSB/JuZO2Wfe/JZVLxE4gSKitrYDaToOfME63pdw4kB33P8ETULzIKSOGQgy7PR9
         coUAe5rpzDfgdo02Q7cg313IZXXcTPpwrqqw/F0XY13Tr8h9pqa7yC6y0F3sP2MSiHjO
         iRmJ8pYujJjqG2vODsJ1K5u8BWLCRk/hEiZw/QF07wwyEU/sdzJGME7dnRL6QF/7tvbY
         Gp7+0MgUb1Ec+kmHkO7W8+fCXGWzU6IpEnWEoSNGIXaRyydA5dvPs5bbfiUTCUpi41uo
         crTqfnEBojwSg0b9oH6rmi8XHZE+e/DpkvzQB4e1eI6WQZBcGWwm1xZrph8nC9LpzPkJ
         PTdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oi+caEFKpbeq987Z4g6YtXizFsBBxbMC/8lTdOUigOo=;
        b=YjZB9YtCWWlR9pogeuPk6JFhqv/UERUFAksqMJtCY/NzdteYIX6nJQq+0x1+iQRWW2
         BeY8MJqZwjsgpH0J9MBsfLewBPjBLhTqufhat66F9nNzdnshhe3awyYvVLmhNf66xkp/
         Kn5yparZwbNm6AaGzkgdn889B38g6xcRMAa3i8gUyxf3loBhu+Mdxt5TPvlmXfj1U0Ju
         tuIx1kG43HRCTU9Lm96XRb72VmuYJk8fT+aR0I+Ow3wnTXFpO9+RriBQdB5j6+xsfBf0
         h0pS8HMGcMMWzVojmIBT1eBKQkSurjtUS9gYukfVDwjRYYI6j8ogJUbwSejAKMnUNMED
         1Z0g==
X-Gm-Message-State: AOAM531hO/FpcAY+D+S6ByRmOfgw6D4Hc5csk3ciUL8i+6W0XRTwtyIc
	f4m6TXnNnpkqRBF0XP8uYM8=
X-Google-Smtp-Source: ABdhPJxj7IZkC4WM4jAi7eDrPebVwkJSMCUsAr2qOMYLomR2+hIFlox2paKJr31++YTwRSlWYvtS2A==
X-Received: by 2002:a17:906:b6cc:: with SMTP id ec12mr5065098ejb.520.1615498651156;
        Thu, 11 Mar 2021 13:37:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls2137704edr.2.gmail; Thu, 11 Mar
 2021 13:37:30 -0800 (PST)
X-Received: by 2002:a05:6402:b85:: with SMTP id cf5mr10884123edb.248.1615498650314;
        Thu, 11 Mar 2021 13:37:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498650; cv=none;
        d=google.com; s=arc-20160816;
        b=OMU/rZpvcGrbUBJOlTbEhM2GB6Ayxa9yBHwmI2S62FuWXwABITsbr47ksaSqVipnpe
         GfmZpxxnt03KrI3JMqvE79CCt+Ioplo8CMBOofPiBTPcTHIhQb4nUHWUvO19DeBD1H4e
         +BxG/eDomq0s9jy5h64QaghSJLPucLMbDm2rlXW7RZImoKvNy/o90cazZkqiRHv6bMJj
         e52RW/1Gn0KKouS6SbGtXi4m74Rpso6M4RMRascQ4s8jStLk0aChBZgKdq2l9+kO9OYH
         6zJMAN9DjUfbyxUNcaL4hXWOQcoU1K+AayA8bO9AadaKqD0sEZlndfQ8aALkS/22+DR2
         AGlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bDwYzUcq1HRoRYrIwl703QQ3e7+1Dgb9ijuIXOFbJHo=;
        b=RSDGO1R+f1TepxtHE2LKJEOz4YQXbjxLsqSNSMWpBCqSW+vmhGQjxNAQe3lYoT737j
         jOkJAEiQ7g15zxwCDflTsmHf1J7aI6AcF652kysAsi6FSSAqJYLXzMT+c6VvrHgRXo+G
         qbhDMEJZo2ShMHLx7bUIJjzPhjXJ/0NsTFEybTgnWHAnU+ezxeggWhxTEpXaeJunAWoP
         VTO+LfshQ9Aamnoh4VsEHdr2pJITb1QrxgDDNCQ5FKoraVdu9gu5KonBZ22o37ZnaDfi
         AmIa1viwk4v89MOPoywH2zzUbyoQvQd5nKug9I1UZkraVDYTfmZj3H6sEt5B9O9Yl4tX
         Sqkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AN4kaYWM;
       spf=pass (google.com: domain of 3my1kyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mY1KYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m18si78467edd.5.2021.03.11.13.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3my1kyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cq11so10524514edb.14
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:30 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:bccc:: with SMTP id
 lw12mr5043065ejb.268.1615498649994; Thu, 11 Mar 2021 13:37:29 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:14 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <da296c4fe645f724922b691019e9e578e1834557.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 02/11] kasan: docs: update overview section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AN4kaYWM;       spf=pass
 (google.com: domain of 3my1kyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mY1KYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Overview" section in KASAN documentation:

- Outline main use cases for each mode.
- Mention that HW_TAGS mode need compiler support too.
- Move the part about SLUB/SLAB support from "Usage" to "Overview".
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 27 +++++++++++++++++++--------
 1 file changed, 19 insertions(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c9484f34da2a..343a683d0520 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -11,17 +11,31 @@ designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
 2. software tag-based KASAN (similar to userspace HWASan),
 3. hardware tag-based KASAN (based on hardware memory tagging).
 
-Software KASAN modes (1 and 2) use compile-time instrumentation to insert
-validity checks before every memory access, and therefore require a compiler
+Generic KASAN is mainly used for debugging due to a large memory overhead.
+Software tag-based KASAN can be used for dogfood testing as it has a lower
+memory overhead that allows using it with real workloads. Hardware tag-based
+KASAN comes with low memory and performance overheads and, therefore, can be
+used in production. Either as an in-field memory bug detector or as a security
+mitigation.
+
+Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
+validity checks before every memory access and, therefore, require a compiler
 version that supports that.
 
-Generic KASAN is supported in both GCC and Clang. With GCC it requires version
+Generic KASAN is supported in GCC and Clang. With GCC, it requires version
 8.3.0 or later. Any supported Clang version is compatible, but detection of
 out-of-bounds accesses for global variables is only supported since Clang 11.
 
-Tag-based KASAN is only supported in Clang.
+Software tag-based KASAN mode is only supported in Clang.
 
-Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
+The hardware KASAN mode (#3) relies on hardware to perform the checks but
+still requires a compiler version that supports memory tagging instructions.
+This mode is supported in Clang 11+.
+
+Both software KASAN modes work with SLUB and SLAB memory allocators,
+while the hardware tag-based KASAN currently only supports SLUB.
+
+Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
 and riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
 Usage
@@ -39,9 +53,6 @@ For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
 CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
 The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
-Both software KASAN modes work with both SLUB and SLAB memory allocators,
-while the hardware tag-based KASAN currently only support SLUB.
-
 For better error reports that include stack traces, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da296c4fe645f724922b691019e9e578e1834557.1615498565.git.andreyknvl%40google.com.
