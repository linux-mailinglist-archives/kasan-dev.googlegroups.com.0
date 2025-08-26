Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUHVWXCQMGQECSNNXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id E5154B35859
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:53 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7e8706abd44sf1339985085a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199633; cv=pass;
        d=google.com; s=arc-20240605;
        b=BIXRLW2KER3thFMZYEyZDmT7pNrquhEoSZ07CUNELljtjVOm1y1wVNlD52a/v3zry6
         umeYc61+bTyKwHNKcyZYVU6anx/sK7dmv+BRB4FOjsslc9dn6XkZOB2zTyK0C1WqrOfM
         s4ciYQSD2t/0L3qzOaT/DZQd3BU/0eCEfbV4CgT21QFBDCfJsSSxsQUsDGZQ/CFtcdde
         gNPtoADm/l1RA1AoJ6GLmcK6egR6mzI9nNMBp+kgftlnm/jHGdYokCeF0fu5wgpWHNKA
         2T6NvD/JOs5BSUxdw9ae4li8023/Ny3Y/DzR4EC5SWJ5djgVDXgMR0L+RNA1cL7jZJ8k
         S0tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rWbWG/f+95oB4tz0s6F/pwE5h4qMnm7Vj9ASfsryEVs=;
        fh=oU5GbVmv3D42flnNBcpk1RxHBUGm71HFbWbXo2gbgiU=;
        b=D4aWlgVI7mc6U1xRS3Bm8J/jyFjSi/Qsscl1p2VzZOSI99zHU3MRj6TOGIm5sR5LH7
         k1HoCV9ok3L46rv9MU2dMbr34a/BofQFX1YML4QB96wL2QySsWm3GCA5dhh6Oc64/yPX
         ajMbPYcrnsm+BdsPBbMQ51vGvKcORak4S1qlvLVeT1v2vKzJT4SQc2tuIs3f6mRzMZmi
         0cvvA8bgv0gGdaVWpmxA4kIbSuZ00oeiMaO4fK44FWKpNQEXQ09NYpukbWBjZv/rxvMv
         LxI4XKx7F6AUjxeL92/OD2apSh81Ujz5nyhTbZuEdnYeHZfQuZ133L0dHSzkjVwtTUzq
         9vfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Ix2/xiBX";
       spf=pass (google.com: domain of 3zxqtaagkccqnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3zXqtaAgKCcQnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199633; x=1756804433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rWbWG/f+95oB4tz0s6F/pwE5h4qMnm7Vj9ASfsryEVs=;
        b=WVjn9szBU4Ls0wlPx0lhWVFsC1qVMA5jZ0itblY+7S13g/HWPzc9kAdCrIpQyotFKh
         PcLs/OjLZMKuSMw+FhN3WVjmLjrjNHc7mOpW6EXLlzx/VCsA63lUifh3zznC15c6IMXq
         +6nvzrSmQ4l9mueTRLvQtgMTDQc+ee3YgFlCrQ7JYoI9qqt8E3Iuy/J5zUG/gLA90lpl
         Hzk4r02bVICgO5OPljVqIP/jlsIvQRNQnJXmkDCWIRXb7QTOnW9F00kHDhiLTpJoUpD3
         ehlWdjq1byTI+EtYozCTzUvg76xbedz9spJ09On9lnZcq0+LnDj9T4Xju08XaYyKMy9B
         5tNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199633; x=1756804433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rWbWG/f+95oB4tz0s6F/pwE5h4qMnm7Vj9ASfsryEVs=;
        b=r6KlMxx70H5rGmosIV0VeXX5Y42OvDI/lBv4dUde2Xd/fvSn9gTPpYghoQXASm3V2C
         PKZiGqA/LDPAm72ChqXR+2v4GYORlvBlJAYhzf4gshy2yjTUut6610dUvSFc3/gD6Ghp
         Ze6r6EmQiSub6R+jrYMoms3O8vbkmHJpV+TJ2pbY+FispEX/kafFprDnzNNc3cPzfjtL
         fvnVVNJOvVwGnaRMFZCOj+C9P1tN1zh7g3KlUUzcjxVom+35P5P/nPDsg/bVati5zCCv
         A4dAaGsadnf38wYtXJGedJtb+kKM/jOLExhpQn2iDtDjiClN5VekAI5gZzK1ju6/vwuC
         Cfww==
X-Forwarded-Encrypted: i=2; AJvYcCUlsZfIcvczLj2rJs7pK37sp7n+91y7NoPCFrs3G1EJMzjQiV9yRasHj921R5OFBgfiyLkCLg==@lfdr.de
X-Gm-Message-State: AOJu0YzFCs9frGNlix+p+OJENTKRYvU0lfOnsTdZ3V+Xw34wRIN99JvQ
	tjHrl72cYEnubkwxWnfBKVnsetmCVVlVkJINzVZz7+Dlthaik9wV/+wC
X-Google-Smtp-Source: AGHT+IFYA2S6/JAKTcf3BSeHN+IhIXkev3XobI5cJB19njmP23nIKuYzKMeofJ6UaDRd3kx74utOew==
X-Received: by 2002:a05:620a:4146:b0:7e8:4161:3ac4 with SMTP id af79cd13be357-7ea10fa11b7mr1283183685a.20.1756199632706;
        Tue, 26 Aug 2025 02:13:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf58I3E9p+GiCWis6vQezY0+5G7kz4tcRpT9zFIF/Bynw==
Received: by 2002:a05:6214:f0b:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70d9522245als66229316d6.1.-pod-prod-01-us; Tue, 26 Aug 2025
 02:13:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuUE6AeSFqtfiK/5CExRziPhCM0fm0xUPsuo+V7niM+6JdD5PGfnTvdFZj3Q14vC2YgjXaP+SP/7s=@googlegroups.com
X-Received: by 2002:a05:620a:3706:b0:7ee:22e9:4558 with SMTP id af79cd13be357-7ee22e94618mr976445985a.51.1756199630189;
        Tue, 26 Aug 2025 02:13:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199630; cv=none;
        d=google.com; s=arc-20240605;
        b=E5L2WFDTCCcSf9B2DpGQRT7Jn2PkrefA2mrjQRiGTg46YQCrRbwfX27iz4jFLCsYps
         ZTA4fXHdyd6Tf+3vo8xPKiDMnSKilOy/1v3VzPB93POshXHcIXZ1EhR4yySjd2gIyVE5
         4c7neVWfwltjkCaZ8RE6UN7fpUy4NLEFXwxMtuvPd6E9iBdGkS9hgl2WHixe1O0UIHkW
         WVnTYTHMgf7MBPWjCBPnq000zwTMFzifG4Zbf3UmR5xexkGbTsMd/uynmgxh0dJL7F+0
         ZrDv7bKPAlqtPWFQcdDmZLQiRMY6Bm+/p2QoeGh5dYxSbAFDCKIltIj/zNlU9KZhisBK
         OvWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wOxgoJJJ8SZ3HeZjErz3bRaIvB/ECPnvmYM5E2IyxbQ=;
        fh=++QmYeg5wPu4N7ddWWLPIKnSgK3hOWM44FYNS9cLfT4=;
        b=VqTw7WDzGO8yF/wUbRpN5nGufvG2hFecEynFCkCn/DoFnY+2c2PDZLYAbUc43ueBRX
         C3/U23IrxUAGVFAuwUn282m0vktYofzzdxdwDuT/orltuauitCy2W962+NaaKAeR7AQY
         Dr1cBkgct1R6+k22pLMxH/0hwC9Xtl36UzqJoeP1NxJgNQkRp/VUpJnxc09789nhdbhw
         /ffl/O8rGrnbsV8E/eX0gGmBEkQPFF1wlhckGykjY1DlaEbNbKzm0jhYI75ORdN6yxPo
         0ZnI3k4X6nWTFf9tuUGtYstbmdlyMCaSe92GkNJFCDKYriqViwP2JZrMLESvm4ljLbgz
         MWbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Ix2/xiBX";
       spf=pass (google.com: domain of 3zxqtaagkccqnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3zXqtaAgKCcQnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebf0f471efsi30843585a.5.2025.08.26.02.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zxqtaagkccqnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id d2e1a72fcca58-76e7ef21d52so10589667b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLL/nTqTdTCWTpw+RZWvHriIZ2O4JTV8vgjQVmUeJqjiYzcSASk4bekXJVcs/wUdoF6IeIy183c58=@googlegroups.com
X-Received: from pfbkw7.prod.google.com ([2002:a05:6a00:94f7:b0:74b:41c0:e916])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a00:14c4:b0:771:fbb0:b1ce with SMTP id d2e1a72fcca58-771fbb0b3dfmr1136261b3a.25.1756199629409;
 Tue, 26 Aug 2025 02:13:49 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:33 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-4-davidgow@google.com>
Subject: [PATCH v4 3/7] kunit: Pass parameterized test context to generate_params()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marie Zhussupova <marievic@google.com>, marievictoria875@gmail.com, rmoar@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Stephen Rothwell <sfr@canb.auug.org.au>, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Ix2/xiBX";       spf=pass
 (google.com: domain of 3zxqtaagkccqnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3zXqtaAgKCcQnk5snqy6qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Marie Zhussupova <marievic@google.com>

To enable more complex parameterized testing scenarios, the
generate_params() function needs additional context beyond just
the previously generated parameter. This patch modifies the
generate_params() function signature to include an extra
`struct kunit *test` argument, giving test users access to the
parameterized test context when generating parameters.

The `struct kunit *test` argument was added as the first parameter
to the function signature as it aligns with the convention of other
KUnit functions that accept `struct kunit *test` first. This also
mirrors the "this" or "self" reference found in object-oriented
programming languages.

This patch also modifies xe_pci_live_device_gen_param() in xe_pci.c
and nthreads_gen_params() in kcsan_test.c to reflect this signature
change.

Reviewed-by: David Gow <davidgow@google.com>
Reviewed-by: Rae Moar <rmoar@google.com>
Acked-by: Marco Elver <elver@google.com>
Acked-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
[Catch some additional gen_params signatures in drm/xe/tests --David]
Signed-off-by: David Gow <davidgow@google.com>
---

Changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-4-marievic@google.com/
- Fixup some additional generate_params signature changes in xe_pci.
- These are also available as a separate patch here:
  https://lore.kernel.org/linux-kselftest/20250821135447.1618942-1-davidgow@google.com/

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-4-marievic@google.com/
- Commit message formatting.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-4-marievic@google.com/
    https://lore.kernel.org/all/20250729193647.3410634-5-marievic@google.com/
    https://lore.kernel.org/all/20250729193647.3410634-6-marievic@google.com/
- generate_params signature changes in xe_pci.c and kcsan_test.c were
  squashed into a single patch to avoid in-between breakages in the series.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 drivers/gpu/drm/xe/tests/xe_pci.c      | 14 +++++++-------
 drivers/gpu/drm/xe/tests/xe_pci_test.h |  9 +++++----
 include/kunit/test.h                   |  9 ++++++---
 kernel/kcsan/kcsan_test.c              |  2 +-
 lib/kunit/test.c                       |  5 +++--
 5 files changed, 22 insertions(+), 17 deletions(-)

diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests/xe_pci.c
index 9c715e59f030..f707e0a54295 100644
--- a/drivers/gpu/drm/xe/tests/xe_pci.c
+++ b/drivers/gpu/drm/xe/tests/xe_pci.c
@@ -44,9 +44,9 @@ KUNIT_ARRAY_PARAM(pci_id, pciidlist, xe_pci_id_kunit_desc);
  *
  * Return: pointer to the next parameter or NULL if no more parameters
  */
-const void *xe_pci_graphics_ip_gen_param(const void *prev, char *desc)
+const void *xe_pci_graphics_ip_gen_param(struct kunit *test, const void *prev, char *desc)
 {
-	return graphics_ip_gen_params(prev, desc);
+	return graphics_ip_gen_params(test, prev, desc);
 }
 EXPORT_SYMBOL_IF_KUNIT(xe_pci_graphics_ip_gen_param);
 
@@ -61,9 +61,9 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_graphics_ip_gen_param);
  *
  * Return: pointer to the next parameter or NULL if no more parameters
  */
-const void *xe_pci_media_ip_gen_param(const void *prev, char *desc)
+const void *xe_pci_media_ip_gen_param(struct kunit *test, const void *prev, char *desc)
 {
-	return media_ip_gen_params(prev, desc);
+	return media_ip_gen_params(test, prev, desc);
 }
 EXPORT_SYMBOL_IF_KUNIT(xe_pci_media_ip_gen_param);
 
@@ -78,9 +78,9 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_media_ip_gen_param);
  *
  * Return: pointer to the next parameter or NULL if no more parameters
  */
-const void *xe_pci_id_gen_param(const void *prev, char *desc)
+const void *xe_pci_id_gen_param(struct kunit *test, const void *prev, char *desc)
 {
-	const struct pci_device_id *pci = pci_id_gen_params(prev, desc);
+	const struct pci_device_id *pci = pci_id_gen_params(test, prev, desc);
 
 	return pci->driver_data ? pci : NULL;
 }
@@ -159,7 +159,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
  * Return: pointer to the next &struct xe_device ready to be used as a parameter
  *         or NULL if there are no more Xe devices on the system.
  */
-const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
+const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc)
 {
 	const struct xe_device *xe = prev;
 	struct device *dev = xe ? xe->drm.dev : NULL;
diff --git a/drivers/gpu/drm/xe/tests/xe_pci_test.h b/drivers/gpu/drm/xe/tests/xe_pci_test.h
index ce4d2b86b778..6d8bc56f7bde 100644
--- a/drivers/gpu/drm/xe/tests/xe_pci_test.h
+++ b/drivers/gpu/drm/xe/tests/xe_pci_test.h
@@ -7,6 +7,7 @@
 #define _XE_PCI_TEST_H_
 
 #include <linux/types.h>
+#include <kunit/test.h>
 
 #include "xe_platform_types.h"
 #include "xe_sriov_types.h"
@@ -25,9 +26,9 @@ struct xe_pci_fake_data {
 
 int xe_pci_fake_device_init(struct xe_device *xe);
 
-const void *xe_pci_graphics_ip_gen_param(const void *prev, char *desc);
-const void *xe_pci_media_ip_gen_param(const void *prev, char *desc);
-const void *xe_pci_id_gen_param(const void *prev, char *desc);
-const void *xe_pci_live_device_gen_param(const void *prev, char *desc);
+const void *xe_pci_graphics_ip_gen_param(struct kunit *test, const void *prev, char *desc);
+const void *xe_pci_media_ip_gen_param(struct kunit *test, const void *prev, char *desc);
+const void *xe_pci_id_gen_param(struct kunit *test, const void *prev, char *desc);
+const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc);
 
 #endif
diff --git a/include/kunit/test.h b/include/kunit/test.h
index fc8fd55b2dfb..8eba1b03c3e3 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -128,7 +128,8 @@ struct kunit_attributes {
 struct kunit_case {
 	void (*run_case)(struct kunit *test);
 	const char *name;
-	const void* (*generate_params)(const void *prev, char *desc);
+	const void* (*generate_params)(struct kunit *test,
+				       const void *prev, char *desc);
 	struct kunit_attributes attr;
 	int (*param_init)(struct kunit *test);
 	void (*param_exit)(struct kunit *test);
@@ -1703,7 +1704,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM(name, array, get_desc)						\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
@@ -1724,7 +1726,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)					\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 49ab81faaed9..a13a090bb2a7 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
  * The thread counts are chosen to cover potentially interesting boundaries and
  * corner cases (2 to 5), and then stress the system with larger counts.
  */
-static const void *nthreads_gen_params(const void *prev, char *desc)
+static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
 {
 	long nthreads = (long)prev;
 
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 0fe61dec5a96..50705248abad 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -700,7 +700,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
-			curr_param = test_case->generate_params(NULL, param_desc);
+			curr_param = test_case->generate_params(&test, NULL, param_desc);
 			test_case->status = KUNIT_SKIPPED;
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "KTAP version 1\n");
@@ -731,7 +731,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 				/* Get next param. */
 				param_desc[0] = '\0';
-				curr_param = test_case->generate_params(curr_param, param_desc);
+				curr_param = test_case->generate_params(&test, curr_param,
+									param_desc);
 			}
 			/*
 			 * TODO: Put into a try catch. Since we don't need suite->exit
-- 
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-4-davidgow%40google.com.
