Return-Path: <kasan-dev+bncBD52JJ7JXILRBKMYWCRQMGQEZSUID6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 67ACA70CFAF
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:43:22 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-3f6a856ae6asf35666651cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:43:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684802601; cv=pass;
        d=google.com; s=arc-20160816;
        b=PZ4jugNzI6I6dPJcejpdTKBQ17IPsdyL5IyPpV2Ruc5udJ6ShKHq/nV8x+NPOIM6Dn
         DhWGQ+xs55rBDxKI+VX2x8pyJjpyTH7k756ftiGZ2g3kli23nIWY1h5qnw8Jfk7rg1yW
         8JAQRPiWsx9LI3WGyLB6Du4wa2dEz2HP2PuwCX0EN5TYDvD89cNcusiimWEq1qTZnWW9
         lLAfG78Uh94iOWCBGEAkPYYStTW7DKtxOHN2ITbS/pGpXjjFPFWpVmVrDPaW7+vCKlsW
         70kY/21Gc18kIRn0iqEEkxUViCvsTY0h0QEXcM/SM1fqmfigFClinh3OsFYVe5ankH66
         vROg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xzc9UmfTFIV08fqrSCNjC1W18UeJ8M6tLI/108dr8ZU=;
        b=mPLK53iYHyssxcROOusyFXPawVOlDpfXA+JTdv+TBo+2URIlaGEUS/F3rzmfMjzdvU
         OmgLAUqdMSkl1n8C2Is7CBKklVC0wIL2rTX2dmnMz6oyIK5PbV+9FT1RXhxDU1QrX9HG
         0xUk0A2HnG2GT6sVW1g67ah56tI8/uGfQUGEmo1ZhF5g3e6X5tkx6BgWFDeNyzxItMPA
         dYa/yB0qAhrLzRa+nNO3i0x96AFLhheUFtzY5EMJ3bL8QHeGQGMXGws1QacQIHhqE/SE
         6M0uEr1+Wrnssw6USoRLuDS/msy7hKhjEA/XKl7ThyeBdD5KVNpbDPCKO3/ZbQjtexKh
         TzSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="bdogDu/L";
       spf=pass (google.com: domain of 3kaxszamkcrsg337ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KAxsZAMKCRsG337FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684802601; x=1687394601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xzc9UmfTFIV08fqrSCNjC1W18UeJ8M6tLI/108dr8ZU=;
        b=Y8LYBpLrJ/PAzUX7x3JLiGRrrqi55MI+x7rray83AOSbbdrHq+5BJ9RRQNBcmAglyn
         lx0XhuaqzX8fvLZdksBfwfzT1Gjt/IP+C8VAofsQA0CEWwZc8/5k0oLF/VbGEaWBAgb0
         Emmc3GAmjneXHsT05K+0hg/DjQiNjmGzkPxmPQ8R+apz+Yp8O2AGRhTp83Fx1jC0QslT
         ASvXcIjkvxWJiwzQxve+m9uqF9rS2pHRNrOLZBJ3ae507pBdoD0gkhnKKrGrCTjq7xk3
         giOAxMdfCeE1/+F0/RWsuDZe3oZjeIlvpeS9u09B2ZCCbhlfXjvNrmRdWeGMgszJLK+P
         BOVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684802601; x=1687394601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xzc9UmfTFIV08fqrSCNjC1W18UeJ8M6tLI/108dr8ZU=;
        b=f06vrd1mqYx2yaT41m1LQYwQvjsKkRggO2v3d+9NmyUEgi/hqMd5MvCOMydlEMF2t2
         Ea2BODNc3WwC4YvH62A4BpR0L44EXMpbt7+16YoY3vCGE2fvRfk1RfEO70Jv0zLHLF2D
         Jp1fv4C8WsaH1mvXy4ZOS7g2Fo+8f6y5sqkOTNtKCRFwotKRIow7O57DPUFLoWKIgwqN
         yKXJLVANjLra3oZF+q0TfUs1ua+j02umsNr3KLTw2CEKTOlzFlvFrt5fnZOw42nNSP/w
         Uvf9KWE0C8GpmZfE7lxJ5r3DzfJymL+LUHE8wzlYR4zLC151iuAgIcSA1FEjO5bjbOxA
         1TTg==
X-Gm-Message-State: AC+VfDz8468RR9gJr4r1GL/2a4JzRXsvOBKPUSv5xSBy3e4WqYhgAIRY
	oJjkdWYfYJzz3xU3ZgbIpvkTsg==
X-Google-Smtp-Source: ACHHUZ7FVsH9kOkqu7GcN2QxQivOv/XGo+7bP2K/xcTem74UGXSDZpT5TBr/EIEg5elmd4Sy9FLr3g==
X-Received: by 2002:a05:622a:1a97:b0:3ec:8ffc:e232 with SMTP id s23-20020a05622a1a9700b003ec8ffce232mr4274908qtc.7.1684802601347;
        Mon, 22 May 2023 17:43:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1910:b0:623:8bf3:d76b with SMTP id
 er16-20020a056214191000b006238bf3d76bls6674756qvb.0.-pod-prod-02-us; Mon, 22
 May 2023 17:43:20 -0700 (PDT)
X-Received: by 2002:a1f:458a:0:b0:440:17f5:10a3 with SMTP id s132-20020a1f458a000000b0044017f510a3mr4557469vka.0.1684802600765;
        Mon, 22 May 2023 17:43:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684802600; cv=none;
        d=google.com; s=arc-20160816;
        b=tvm8xwLuUSQahLFtm907Mtx7snCbEeTd8N1MptYTTUfJcvDgEMj74UAvniJnwFWCZq
         0TNTy/eU8RGkTjjiEKw2zgcwiOEHZIqykvejx0dqeeUYiJ/ltfFMOPrjFJcLaKycZnL3
         22t4kpRRVduXfqCei4Kp4C2NBn4Bih20Kwz4txd82GVWBWOguYUWNeI46SqlMXzpiebJ
         m5vUkFa7kcFB4tEieoPDODEAtbMTEc1J72tg8wHp4fugj5LyD+08D854WZIz6Uma5RXL
         RWmbDKUheVCU4YfgnD3/7oz0XHzzv4bHjklGYCdzlqoHGWlyvvdhuE+YQAqDcHWeLdaj
         oChg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bX87CylYnN+5c55ItUvtBMTDdL52LhDBMQG45ADuUIs=;
        b=FsNYLKGitzVn3ic+s1Eq2ky2/4Jkihm4QFPgjvpXbGjc+GlPn/yZz0vjXrypLke5+Y
         vsu6N0j2iLGOMSEEU3zvdGcjlhA7GyQTZoUTzD8Nzi8IRiCACXDiGGmXnuUF7uRhl7FE
         EEzY8hYAi1OUgGonc+tUGAN+Ij4Kmqmj2c/vBYYU45i67dC9a3gWc/0xlPQqItJEKFms
         U+E2yQtwTTd1c4lcHN8oKCXX6iDSRKkSS3KKLthYdnvrr1DHCuQjambBgbQr7IogHcG7
         q3xqYCcxtZhC9krASBhCDa/kaaUpcMJc5PO+S+SKhf2pUnH0cp/s+7NSTvMX8zqPC6ts
         IsZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="bdogDu/L";
       spf=pass (google.com: domain of 3kaxszamkcrsg337ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KAxsZAMKCRsG337FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 17-20020a0561220a1100b0043fc21a7c27si333154vkn.4.2023.05.22.17.43.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 17:43:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kaxszamkcrsg337ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-ba8b0fc0d35so9301946276.0
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 17:43:20 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:3d33:90fe:6f02:afdd])
 (user=pcc job=sendgmr) by 2002:a25:d55:0:b0:ba8:9455:85b9 with SMTP id
 82-20020a250d55000000b00ba8945585b9mr5274091ybn.4.1684802600447; Mon, 22 May
 2023 17:43:20 -0700 (PDT)
Date: Mon, 22 May 2023 17:43:09 -0700
In-Reply-To: <20230523004312.1807357-1-pcc@google.com>
Message-Id: <20230523004312.1807357-3-pcc@google.com>
Mime-Version: 1.0
References: <20230523004312.1807357-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.698.g37aff9b760-goog
Subject: [PATCH v4 2/3] mm: Call arch_swap_restore() from unuse_pte()
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="bdogDu/L";       spf=pass
 (google.com: domain of 3kaxszamkcrsg337ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KAxsZAMKCRsG337FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

We would like to move away from requiring architectures to restore
metadata from swap in the set_pte_at() implementation, as this is not only
error-prone but adds complexity to the arch-specific code. This requires
us to call arch_swap_restore() before calling swap_free() whenever pages
are restored from swap. We are currently doing so everywhere except in
unuse_pte(); do so there as well.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a99ae05d6bbc4f
Suggested-by: David Hildenbrand <david@redhat.com>
Acked-by: David Hildenbrand <david@redhat.com>
Acked-by: "Huang, Ying" <ying.huang@intel.com>
Reviewed-by: Steven Price <steven.price@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
 mm/swapfile.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/mm/swapfile.c b/mm/swapfile.c
index 274bbf797480..e9843fadecd6 100644
--- a/mm/swapfile.c
+++ b/mm/swapfile.c
@@ -1794,6 +1794,13 @@ static int unuse_pte(struct vm_area_struct *vma, pmd_t *pmd,
 		goto setpte;
 	}
 
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, page_folio(page));
+
 	/* See do_swap_page() */
 	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
 	BUG_ON(PageAnon(page) && PageAnonExclusive(page));
-- 
2.40.1.698.g37aff9b760-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230523004312.1807357-3-pcc%40google.com.
