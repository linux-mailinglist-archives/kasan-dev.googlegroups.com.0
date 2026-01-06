Return-Path: <kasan-dev+bncBC6ZNIURTQNRBM456XFAMGQELFB7MCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DC59CF9EC7
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 19:04:37 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-64cfe5a2147sf1751773a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 10:04:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767722677; cv=pass;
        d=google.com; s=arc-20240605;
        b=lL6dlkdy+LmrfQyOa6U06CLOwAx0RS1pBDgvYBr+r8ZPWCNGQVqnj/4UAbCVO593Ya
         gRd0Kt3w2kv2Htu8tTgO4UKagNXwT1rsyBP0GW5HIkXin042Tbe9HmgJ+qQzpakzd0Jt
         /fpKTyrXfAZxC5ZbFfZXzz815lvNYCvnxa1e803Fpu9FAGwvcbJ0ksgc4vB9YXgfeeZm
         cdboV/yC8ngFC/vT9N6hTUW092oVl+MZHbpuzehqM8Djv96appIDR5yFo5hJa9RHtWmU
         dT3bt8GbCmtrhSC+qiomAwp2bvpo7dfD3YGRt76thROZclOmz4TFhfKmfuTE6l0tOr9z
         YqwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Ga0NabSdJyH/qw08FWB4DhB0HG+ONWkvrU/MaxmDOc4=;
        fh=s6iGvl8fcmX91d7UXMw1fWwxajqUQtiqCzn5nl4NGzc=;
        b=gNwMTy5KtWJtDh44mL2mio46s/FdgxinBXsdZcHDFVERy7QBsitgExOvS6vk46MnZ0
         9YJL15CNCfDWoUXoPxtMUfWbTPER8TSEI3ZKuhShH5SKWFbA6pFixuJLtV5YQ/a7uxye
         RBU9Lz0xbpwoN+XCIGgq94xacK8C/ZsSTzEC2W7fLsacWEqtYpQYQxKYXXrkQXZISCnl
         cJxN5z+Qh/bJ0vNUL/1TMVRZMgQsFiuLpyqBXsln/iuYC/1D9uN5QpuTU9kyQr9QSXPx
         nC2GoNq3OKgOFeNPbGFnEyH18wP5XAfoBWAcDOh4SXqzjL6yAooQyGL0VxoSGiJJdXNc
         8KWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=EPKUh3AH;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767722677; x=1768327477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ga0NabSdJyH/qw08FWB4DhB0HG+ONWkvrU/MaxmDOc4=;
        b=LFS/QOMgY5vtI/KVQ2iR4nlyCfzI+x8gmpZwpqsU146SdL7fDIqVQVT37swJSe3e5x
         C9PtL4d83G4yhTyxwpxIQQ6T+UwOyk5Gplv14pc5gYxSc5iJjjOiZB4PdCkQhLTjD6M3
         OFujoOesMYWjNadMoHv1vHOEy9XRBmWx6UPiB11z/Xj5TYnkHoiXaLB1be5FWENYh2re
         a3FqiNkp1UFWJqgsBfcaO/DF5tlpE50bWV50/UZcCpwKuxs9l+KeZ9u2iBZ23cQe9dcW
         9SJIDG8Ly0KTrGVrxPQ6+xyWZedGf2beNFJA6DLr4ngwY0YvgMcaiT9QMS9psnw04tdX
         NXHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767722677; x=1768327477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Ga0NabSdJyH/qw08FWB4DhB0HG+ONWkvrU/MaxmDOc4=;
        b=K75VYjVLMYAwi+qMPOd7Mnz8hGqHysqp0+vJRpSZ3R4DnjzH001mvqN3NZUy38pwB6
         I5I3txv2KDLKy6vWtN/5eJPpveMLC8dTi0xbCNOEJlLcq34mcf1ET2HdW2KlKdAyBl16
         KUcN8PwLpmws3Jsb46b/Mhmtku7eVudLlKzH86hflQOsQ95Z1TM9rhkG/Hb74+cJonwN
         wPQ1drB05Rjm8B0JxSTgqU/yfqpuKywYZuNISWhfDauvfMTbnPy+2UEYT4164ShbJSIU
         AyrKjTsWwx50yavwRgX5Y+rHf1zhW6CViN0TeQuGzSgA4Yu/b7R0V23dvxogxE1apIrd
         zvkQ==
X-Forwarded-Encrypted: i=2; AJvYcCVEteyM777T/gaiq+AP3gKo+K6z3YO0LE2K8BvKYURZwNylrQKgVuHDtUMeViAzMNrVgBfUtA==@lfdr.de
X-Gm-Message-State: AOJu0Yy6qQIWxolgPIs3KPk/+wNiAOyuiYqvvYPHOE/77kCBL5wMuME8
	wKgMjJhu65AlyIKTCdrobmF8Jhq8QIZ4F0sazrmA+z+OlgMU9DcAwlXr
X-Google-Smtp-Source: AGHT+IEn2wwXGiN4Z5oOrcfUpMsNvJjqNsOnZCUCbQC4OVmFNDWyIPw2yp2jKeZkWc+gAtQM1MKDjA==
X-Received: by 2002:a05:6402:234d:b0:63c:3c63:75ed with SMTP id 4fb4d7f45d1cf-65079674a7dmr3715025a12.22.1767722676602;
        Tue, 06 Jan 2026 10:04:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYiQD/kzHFWdBu4C+s/qhHU8hSRfw8BtQhKpgSKJ9rpeQ=="
Received: by 2002:aa7:de15:0:b0:644:fc33:37b6 with SMTP id 4fb4d7f45d1cf-65074900007ls1232563a12.1.-pod-prod-08-eu;
 Tue, 06 Jan 2026 10:04:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVES8bhjDUOZRKu9beFozEEDGSal/M37PUXNeH4dsfsxwXmqC8gUGVhlkRLbBxqMH7kaPzSLYIRFaE=@googlegroups.com
X-Received: by 2002:a17:907:e90:b0:b80:2b9b:39e4 with SMTP id a640c23a62f3a-b844501195dmr1456866b.55.1767722673563;
        Tue, 06 Jan 2026 10:04:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767722673; cv=none;
        d=google.com; s=arc-20240605;
        b=BzqF8y/QeTT+74KGyq0YG4O87CSXfUHzCbFbtDerkRN8HygO95f707AwAdHQlmdbah
         VCpdb4RSKvZL5k121NGSq9hGg8SSSXwGXIM6LoCmWI+BFFbip5fk9BIDKjHLeih++OJb
         lybbuP/3Z9XEk8qXJ2p0LyEXi2OvTfLjVPmDo9iSskbTA6F8o3JZ329XXs7WNwEXNeNN
         Q5saNBcDsMR4Hh8NUI2XpKwv4tyk3SIWu/jJ0WKqJ5VjZ+lP7GlTfmGJY2Oj8GNkFsEk
         mTa9IG+fJVIU20nuwEvVq93jR+4z034UJPQe6BmBbAhTbJwpjNYPgVi24Eaz9oqeyY6R
         g8BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Var1b/I8bDakbx+YOmwdIeXekCHIb3hIZrcAPdgbBnI=;
        fh=3vXzI7kTdcSSif8qbAK+YnfciThpy1Uq7JN/KbRH27s=;
        b=Slbg8fSjpazxxidYgLHOME8woEPoklS+dnWhLly2c2zwVoNDnmSkhm+6nsE8Aml31D
         sPsZiAdR/GxRLIZYzphrm2Nk0CsQR3DKpLUeUF4aEvnyhfEochfT1ykPAVoXsmknehjN
         NRlASbCIVW9PtkHDshiwh7Mp8BHTJpUpSIhdpWeH0o2Ua73biMncVrGqnW9c+tMGNoz6
         fa+h9IEbSc+AaUqcmAeHt7a9ATEs/Zp07filPmhMUFuM3YIA8Fo3L8Vd98pDx6tPi+1j
         XzeaQcIP4qZXJhLNE7QbOFv9tJ8SsJeD8A6s9bdvw4Mm23woZq1sfEuTnAI1URmBmVYX
         o8vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=EPKUh3AH;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8440e5c9desi3487966b.4.2026.01.06.10.04.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Jan 2026 10:04:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-47d1d8a49f5so8566815e9.3
        for <kasan-dev@googlegroups.com>; Tue, 06 Jan 2026 10:04:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUkXxSr6yrLM9liIiX4FGOarXCSyyicZ2MuufjyDA247fJLIcQK8kZ28mJofpvVMM2LSf/LHgJxIXk=@googlegroups.com
X-Gm-Gg: AY/fxX5VdfW4V+nCsgjevHb5tfv4HgTiGK514CXdlE4kx9T9HgYunwvV5eJFwv/v0w9
	dsA3RZT6QUGweH/wYD/2Ll+e1GAgeccJz09sSnYF1rJSi2x69hMSnhth+2mAMXEQE5xQ2By4En5
	YqrauRK68M89qeege8/qlUcC7O8BR2tw0ltLNe2ICXgWsqGLaPySJiC21wvfnfNXAwcTFiCkZqe
	DkJaoECPjAWlb9sVFWMT1B0skPbDEq+/xIRk64gtbipR14Nh/7rOvnZaeOMp2FKNosBQGPHeioV
	7rtY2h9atIPhF4lwaYUffHeu4NDopV1oImdogibz4dWThJHHHoGON5a/PFxMrH3f8xAg/VYqr+e
	0vQUJRSBQ9kAP+9R0KcpQGNYaMJrWuElFn6Guwvr+NUtgWLnYDft65bfHekU9RhgC3eqqjRa+zR
	QHdsvpl+eTCeUuNCxL3keCSc5ymrIjk5GWrIoYqoZdcM1a7vJ17nVLCKT0Lr5WJQQEP1EAXxiU
X-Received: by 2002:a05:600c:34c6:b0:47d:3ffa:980e with SMTP id 5b1f17b1804b1-47d7f09b759mr35979615e9.28.1767722672877;
        Tue, 06 Jan 2026 10:04:32 -0800 (PST)
Received: from localhost.localdomain (host-92-26-102-188.as13285.net. [92.26.102.188])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-432bd5ee243sm5519630f8f.31.2026.01.06.10.04.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Jan 2026 10:04:32 -0800 (PST)
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
To: LKML <linux-kernel@vger.kernel.org>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Jann Horn <jannh@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH] x86/kfence: Avoid writing L1TF-vulnerable PTEs
Date: Tue,  6 Jan 2026 18:04:26 +0000
Message-Id: <20260106180426.710013-1-andrew.cooper3@citrix.com>
X-Mailer: git-send-email 2.39.5
MIME-Version: 1.0
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=google header.b=EPKUh3AH;       spf=pass
 (google.com: domain of andrew.cooper3@citrix.com designates
 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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

For native, the choice of PTE is fine.  There's real memory backing the
non-present PTE.  However, for XenPV, Xen complains:

  (XEN) d1 L1TF-vulnerable L1e 8010000018200066 - Shadowing

To explain, some background on XenPV pagetables:

  Xen PV guests are control their own pagetables; they choose the new PTE
  value, and use hypercalls to make changes so Xen can audit for safety.

  In addition to a regular reference count, Xen also maintains a type
  reference count.  e.g. SegDesc (referenced by vGDT/vLDT),
  Writable (referenced with _PAGE_RW) or L{1..4} (referenced by vCR3 or a
  lower pagetable level).  This is in order to prevent e.g. a page being
  inserted into the pagetables for which the guest has a writable mapping.

  For non-present mappings, all other bits become software accessible, and
  typically contain metadata rather a real frame address.  There is nothing
  that a reference count could sensibly be tied to.  As such, even if Xen
  could recognise the address as currently safe, nothing would prevent that
  frame from changing owner to another VM in the future.

  When Xen detects a PV guest writing a L1TF-PTE, it responds by activating
  shadow paging. This is normally only used for the live phase of
  migration, and comes with a reasonable overhead.

KFENCE only cares about getting #PF to catch wild accesses; it doesn't care
about the value for non-present mappings.  Use a fully inverted PTE, to
avoid hitting the slow path when running under Xen.

While adjusting the logic, take the opportunity to skip all actions if the
PTE is already in the right state, half the number PVOps callouts, and skip
TLB maintenance on a !P -> P transition which benefits non-Xen cases too.

Fixes: 1dc0da6e9ec0 ("x86, kfence: enable KFENCE for x86")
Tested-by: Marco Elver <elver@google.com>
Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
---
CC: Alexander Potapenko <glider@google.com>
CC: Marco Elver <elver@google.com>
CC: Dmitry Vyukov <dvyukov@google.com>
CC: Thomas Gleixner <tglx@linutronix.de>
CC: Ingo Molnar <mingo@redhat.com>
CC: Borislav Petkov <bp@alien8.de>
CC: Dave Hansen <dave.hansen@linux.intel.com>
CC: x86@kernel.org
CC: "H. Peter Anvin" <hpa@zytor.com>
CC: Andrew Morton <akpm@linux-foundation.org>
CC: Jann Horn <jannh@google.com>
CC: kasan-dev@googlegroups.com
CC: linux-kernel@vger.kernel.org

v1:
 * First public posting.  This went to security@ first just in case, and
   then I got districted with other things ahead of public posting.
---
 arch/x86/include/asm/kfence.h | 29 ++++++++++++++++++++++++-----
 1 file changed, 24 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index ff5c7134a37a..acf9ffa1a171 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -42,10 +42,34 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
 	unsigned int level;
 	pte_t *pte = lookup_address(addr, &level);
+	pteval_t val;
 
 	if (WARN_ON(!pte || level != PG_LEVEL_4K))
 		return false;
 
+	val = pte_val(*pte);
+
+	/*
+	 * protect requires making the page not-present.  If the PTE is
+	 * already in the right state, there's nothing to do.
+	 */
+	if (protect != !!(val & _PAGE_PRESENT))
+		return true;
+
+	/*
+	 * Otherwise, invert the entire PTE.  This avoids writing out an
+	 * L1TF-vulnerable PTE (not present, without the high address bits
+	 * set).
+	 */
+	set_pte(pte, __pte(~val));
+
+	/*
+	 * If the page was protected (non-present) and we're making it
+	 * present, there is no need to flush the TLB at all.
+	 */
+	if (!protect)
+		return true;
+
 	/*
 	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
 	 * with interrupts disabled. Therefore, the below is best-effort, and
@@ -53,11 +77,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	 * lazy fault handling takes care of faults after the page is PRESENT.
 	 */
 
-	if (protect)
-		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
-	else
-		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
-
 	/*
 	 * Flush this CPU's TLB, assuming whoever did the allocation/free is
 	 * likely to continue running on this CPU.

base-commit: 7f98ab9da046865d57c102fd3ca9669a29845f67
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260106180426.710013-1-andrew.cooper3%40citrix.com.
