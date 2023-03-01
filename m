Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEUJ72PQMGQEOXWPUNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id DB21E6A71AF
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 18:00:04 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id c4-20020a056830000400b00690e55c7680sf6676269otp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 09:00:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677690003; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ir9QjsTXyvnnqepdRzOEIpENAdb/lWHqbEYiLYeKuqaKOvKrVOFxVE/xfK4mgi9NRZ
         Oz5CfE4zwW2STTLsUrVTCsrsFs+gEzDBks3WjNMkfpXw7pCx76HSm7YK0kBD+AeXgG4y
         W49XqE5wmhQfS4nPrf0LakIwj6hSi7RWnQZQMhKxGOXltPCxCuD9sbxsv45P59u0bo4G
         bIIBZumreoRRwqzUL6+c0mN1Uq6cUjf2UpAE62Ox8mWFNP9AFbJZcLBdHMdMQUSM3D21
         vy6Q7pwYKDkeNlhx/7uUHkPO6rhG/+JHehJ4n3UzyKfIA+7d0i3GnEhThp6A6iYR98e/
         M8xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=76I/lpoHN3MWBC4hctF/oM5Gp6AL0WTwgmYh0gShOz0=;
        b=XRw8cAU0TECP4qphlcWo6635XMk5l4ErmtQy2EKVE9svEgIs43e3uYp/OA6DBPhASm
         CYJlo4O6TlR6Nq3anl7l0p/WGaPGJm+g1JXCszSkV9lW9ibpPFt4JURkdosSNvrv8/Qp
         c/LyhiKN4mB5fhHYr1uMWsnNM8x3TQN5Vnc+kmQu8EByG7pjAtPejcwL7hAWYsvwx2V0
         sfpXWLn8Phl5coR3hqBo25psMhYMIuaUPOPzpqSrMIvpXaFPW1XpF4+tTR/y0ec62jqL
         CYcsVepcdbhalSAyh+aQUJ/1axR2UNli/qBcXZU6in9blniQTWNBKOj0Dljb6Jn8crJq
         3lrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=76I/lpoHN3MWBC4hctF/oM5Gp6AL0WTwgmYh0gShOz0=;
        b=tn2JgPeYoik7tnXuIV9yv8NLqgyQK5PERU5BhAaOlZPSvZ9lPqK3OTUjysW151y2NZ
         QHZe3E6Wk1gYvJJJLxehA3g/ZIO7tfPGGoQ2m8+GVyvZWPBYBkwY855vwc69RizMOhxa
         m1lvcb4cioahGjlXLbfTlkJ+sHm7ADL3M0Sb9Wx43H7CNFkmzfbjFUKhRZMFsOIHYgG9
         QTdTi0EH7P8euLXEVa0hnY28Yt+l2q+xabdbNQbSff7cVIZATUNe+sk4UM1SNcSWsCJX
         KyhBpRV3CDAxTR4QbX7cCgsx27BNTSohV46aFUasMSKrUo/Sa89oVUmo7O8wTz73rwvq
         psGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=76I/lpoHN3MWBC4hctF/oM5Gp6AL0WTwgmYh0gShOz0=;
        b=HShJhVqr/H51jImZ2RG/r86NhMtWZo4SdCFWeUuFGTZ//NNL1MYdkfMqRjRTnIC3QG
         WA6c0OqpbQcOWY2rudqfYcTyetQ4Zq/d6/XgJz7MSjxOB+fIb9eNbiqKsqg1AV2V7tKp
         YQIRfX9Bqd4p9a7G4cqQmP3y8M5SqAcsWoo6h2SYXgOQiG+erX4YH2I1EkH05aqJbx2Y
         xSNjTrTTUTkYVcepwjaWHH4WXBWBqRYbbk4h2h9G524Bq8voD3iB7cDunT+Yd5kEHc4L
         TUpxJG5KaxYPzshMtQsN5d9xEGvUbeKgAvK1g5LTQXOIF77/K3XJz8hcG6tXiLXKGQoS
         frAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUeh6V8BWXRunbhSe6xr47BYX/ApQriPkmQPh58J39L8RemecM7
	WoljYchqZ57vei2lGFHJnuc=
X-Google-Smtp-Source: AK7set+l1P07Br4nZn+E1eZXcybQSMjM3OEvwvog+4RYWNsLkqjAiRe/1i4nHzwME2fjRnZEdjS1Ew==
X-Received: by 2002:aca:2809:0:b0:384:11ed:a879 with SMTP id 9-20020aca2809000000b0038411eda879mr2194567oix.10.1677690002948;
        Wed, 01 Mar 2023 09:00:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:244b:b0:694:158d:37c8 with SMTP id
 x11-20020a056830244b00b00694158d37c8ls1258575otr.11.-pod-prod-gmail; Wed, 01
 Mar 2023 09:00:02 -0800 (PST)
X-Received: by 2002:a9d:188:0:b0:68b:cc5c:184b with SMTP id e8-20020a9d0188000000b0068bcc5c184bmr4033730ote.20.1677690002088;
        Wed, 01 Mar 2023 09:00:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677690002; cv=none;
        d=google.com; s=arc-20160816;
        b=s5tvmxd1bi2bVzDr0YaeVy/Il8T4s1mQkKocRdKzpWXijtqv6k1sC3jcGkSGHqt7VY
         0vio5s7NNDIKCexau54QW+0n64pO0xyzfWEdj4DbbEbPQ518BLkpDCRB3Pc/yirwJ/YV
         ivrA8mhbA4cJhAGMravNj+bZpFtkXAnucwvjYnx0qbGUaK72igqFMw8gLr3E4N5a5HOK
         EZSNhACgQoatLxnQhtGrOljwJCAjIBLH0FlOlgzcTyyFKNImYHllVLLaBm64i54poojE
         b3NMJG0e3wBE12soA6yCLFURnY4RcXecvSN8nqL8biysgOkgoaafJFnJlfjSHCABe7F2
         epAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=qEpa3RETl/xld0LCpoF0YHKhdeUIUgyJFbzpbRXoLdM=;
        b=Br9SAgoLrUvk3feObkEu/lpOLGiCfjZFT4f20gYGA3R3izuqMVSIcg9sOas9oHQMSQ
         Ommx4QQZQkmGdDIb+fgVLb1twOs1mt/Q/oSnlHfFfAQsMF447r21hhaeMvo0TtAbl2kr
         KqyZHw6PnxlPjzU5HvXMd7ZM2ofrRwyUWKhU8CgOnIXG1XMm0Js7BE61RgdCOYx5D/B/
         MssF78Dt6nQfqL1VWXhuPGYwn4dfEZGzVAQDJyoWfJp0kr5aS9iaguaBI6A/qRzOlgtG
         N1F8by9Tl2xgfM1wXavu1wwMPU8UTef5m9MNdQ0pVNwzD84c5aBFhEfRwOGa9PPRJCNs
         lILQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 39-20020a9d032a000000b006941e4e6ac6si365716otv.4.2023.03.01.09.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Mar 2023 09:00:02 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CD99D61321;
	Wed,  1 Mar 2023 17:00:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B51A5C433D2;
	Wed,  1 Mar 2023 16:59:58 +0000 (UTC)
Date: Wed, 1 Mar 2023 16:59:55 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	=?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Weizhao Ouyang <o451686892@gmail.com>,
	=?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>,
	Peter Collingbourne <pcc@google.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
Message-ID: <Y/+Ei5boQh+TFj7Q@arm.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
 <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
 <Y/4nJEHeUAEBsj6y@arm.com>
 <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 28, 2023 at 10:50:46PM +0100, Andrey Konovalov wrote:
> On Tue, Feb 28, 2023 at 5:09=E2=80=AFPM Catalin Marinas <catalin.marinas@=
arm.com> wrote:
> > On Mon, Feb 27, 2023 at 03:13:45AM +0100, Andrey Konovalov wrote:
> > > +Catalin, would it be acceptable to implement a routine that disables
> > > in-kernel MTE tag checking (until the next
> > > mte_enable_kernel_sync/async/asymm call)? In a similar way an MTE
> > > fault does this, but without the fault itself. I.e., expose the part
> > > of do_tag_recovery functionality without report_tag_fault?
> >
> > I don't think we ever re-enable MTE after do_tag_recovery(). The
> > mte_enable_kernel_*() are called at boot. We do call
> > kasan_enable_tagging() explicitly in the kunit tests but that's a
> > controlled fault environment.
>=20
> Right, but here we don't want to re-enable MTE after a fault, we want
> to suppress faults when printing an error report.
>=20
> > IIUC, the problem is that the kernel already got an MTE fault, so at
> > that point the error is not really recoverable.
>=20
> No, the problem is with the following sequence of events:
>=20
> 1. KASAN detects a memory corruption and starts printing a report
> _without getting an MTE fault_. This happens when e.g. KASAN sees a
> free of an invalid address.
>=20
> 2. During error reporting, an MTE fault is triggered by the error
> reporting code. E.g. while collecting information about the accessed
> slab object.
>=20
> 3. KASAN tries to print another report while printing a report and
> goes into a deadlock.
>=20
> If we could avoid MTE faults being triggered during error reporting,
> this would solve the problem.

Ah, I get it now. So we just want to avoid triggering a benign MTE
fault.

> > If we want to avoid a
> > fault in the first place, we could do something like
> > __uaccess_enable_tco() (Vincenzo has some patches to generalise these
> > routines)
>=20
> Ah, this looks exactly like what we need. Adding
> __uaccess_en/disable_tco to kasan_report_invalid_free solves the
> problem.
>=20
> Do you think it would be possible to expose these routines to KASAN?

Yes. I'm including Vincenzo's patch below (part of fixing some potential
strscpy() faults with its unaligned accesses eager reading; we'll get to
posting that eventually). You can add some arch_kasan_enable/disable()
macros on top and feel free to include the patch below.

Now, I wonder whether we should link those into kasan_disable_current().
These functions only deal with the depth for KASAN_SW_TAGS but it would
make sense for KASAN_HW_TAGS to enable tag-check-override so that we
don't need to bother with a match-all tags on pointer dereferencing.

----8<----------------------------
From 0dcfc84d8b984001219cc3c9eaf698c26286624c Mon Sep 17 00:00:00 2001
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Date: Thu, 13 Oct 2022 07:46:23 +0100
Subject: [PATCH] arm64: mte: Rename TCO routines

The TCO related routines are used in uaccess methods and
load_unaligned_zeropad() but are unrelated to both even if the naming
suggest otherwise.

Improve the readability of the code moving the away from uaccess.h and
pre-pending them with "mte".

Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/include/asm/mte-kasan.h      | 81 +++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h            | 12 ----
 arch/arm64/include/asm/uaccess.h        | 66 +++-----------------
 arch/arm64/include/asm/word-at-a-time.h |  4 +-
 4 files changed, 93 insertions(+), 70 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mt=
e-kasan.h
index 9f79425fc65a..598be32ed811 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -13,8 +13,73 @@
=20
 #include <linux/types.h>
=20
+#ifdef CONFIG_KASAN_HW_TAGS
+
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return static_branch_unlikely(&mte_async_or_asymm_mode);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return false;
+}
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_ARM64_MTE
=20
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
+static inline void __mte_disable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+static inline void __mte_enable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
+static inline void __mte_disable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		 __mte_disable_tco();
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		__mte_enable_tco();
+}
+
 /*
  * These functions are meant to be only used from KASAN runtime through
  * the arch_*() interface defined in asm/memory.h.
@@ -138,6 +203,22 @@ void mte_enable_kernel_asymm(void);
=20
 #else /* CONFIG_ARM64_MTE */
=20
+static inline void __mte_disable_tco(void)
+{
+}
+
+static inline void __mte_enable_tco(void)
+{
+}
+
+static inline void __mte_disable_tco_async(void)
+{
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+}
+
 static inline u8 mte_get_ptr_tag(void *ptr)
 {
 	return 0xFF;
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 20dd06d70af5..c028afb1cd0b 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -178,14 +178,6 @@ static inline void mte_disable_tco_entry(struct task_s=
truct *task)
 }
=20
 #ifdef CONFIG_KASAN_HW_TAGS
-/* Whether the MTE asynchronous mode is enabled. */
-DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
-
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return static_branch_unlikely(&mte_async_or_asymm_mode);
-}
-
 void mte_check_tfsr_el1(void);
=20
 static inline void mte_check_tfsr_entry(void)
@@ -212,10 +204,6 @@ static inline void mte_check_tfsr_exit(void)
 	mte_check_tfsr_el1();
 }
 #else
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return false;
-}
 static inline void mte_check_tfsr_el1(void)
 {
 }
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uacc=
ess.h
index 5c7b2f9d5913..057ec1882326 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -136,55 +136,9 @@ static inline void __uaccess_enable_hw_pan(void)
 			CONFIG_ARM64_PAN));
 }
=20
-/*
- * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
- * affects EL0 and TCF affects EL1 irrespective of which TTBR is
- * used.
- * The kernel accesses TTBR0 usually with LDTR/STTR instructions
- * when UAO is available, so these would act as EL0 accesses using
- * TCF0.
- * However futex.h code uses exclusives which would be executed as
- * EL1, this can potentially cause a tag check fault even if the
- * user disables TCF0.
- *
- * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
- * and reset it in uaccess_disable().
- *
- * The Tag check override (TCO) bit disables temporarily the tag checking
- * preventing the issue.
- */
-static inline void __uaccess_disable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-static inline void __uaccess_enable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-/*
- * These functions disable tag checking only if in MTE async mode
- * since the sync mode generates exceptions synchronously and the
- * nofault or load_unaligned_zeropad can handle them.
- */
-static inline void __uaccess_disable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		 __uaccess_disable_tco();
-}
-
-static inline void __uaccess_enable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		__uaccess_enable_tco();
-}
-
 static inline void uaccess_disable_privileged(void)
 {
-	__uaccess_disable_tco();
+	__mte_disable_tco();
=20
 	if (uaccess_ttbr0_disable())
 		return;
@@ -194,7 +148,7 @@ static inline void uaccess_disable_privileged(void)
=20
 static inline void uaccess_enable_privileged(void)
 {
-	__uaccess_enable_tco();
+	__mte_enable_tco();
=20
 	if (uaccess_ttbr0_enable())
 		return;
@@ -302,8 +256,8 @@ do {									\
 #define get_user	__get_user
=20
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async(=
) and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() an=
d
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __get_kernel_nofault(dst, src, type, err_label)			\
@@ -312,10 +266,10 @@ do {									\
 	__typeof__(src) __gkn_src =3D (src);				\
 	int __gkn_err =3D 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_get_mem("ldr", *((type *)(__gkn_dst)),			\
 		      (__force type *)(__gkn_src), __gkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__gkn_err))					\
 		goto err_label;						\
@@ -388,8 +342,8 @@ do {									\
 #define put_user	__put_user
=20
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async(=
) and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() an=
d
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __put_kernel_nofault(dst, src, type, err_label)			\
@@ -398,10 +352,10 @@ do {									\
 	__typeof__(src) __pkn_src =3D (src);				\
 	int __pkn_err =3D 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_put_mem("str", *((type *)(__pkn_src)),			\
 		      (__force type *)(__pkn_dst), __pkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__pkn_err))					\
 		goto err_label;						\
diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/a=
sm/word-at-a-time.h
index 1c8e4f2490bf..f3b151ed0d7a 100644
--- a/arch/arm64/include/asm/word-at-a-time.h
+++ b/arch/arm64/include/asm/word-at-a-time.h
@@ -55,7 +55,7 @@ static inline unsigned long load_unaligned_zeropad(const =
void *addr)
 {
 	unsigned long ret;
=20
-	__uaccess_enable_tco_async();
+	__mte_enable_tco_async();
=20
 	/* Load word from unaligned pointer addr */
 	asm(
@@ -65,7 +65,7 @@ static inline unsigned long load_unaligned_zeropad(const =
void *addr)
 	: "=3D&r" (ret)
 	: "r" (addr), "Q" (*(unsigned long *)addr));
=20
-	__uaccess_disable_tco_async();
+	__mte_disable_tco_async();
=20
 	return ret;
 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y/%2BEi5boQh%2BTFj7Q%40arm.com.
