Return-Path: <kasan-dev+bncBC7OBJGL2MHBBONXVWBAMGQEODH5L7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F012338C7E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 13:16:58 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id u5sf17931123qkj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 04:16:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615551417; cv=pass;
        d=google.com; s=arc-20160816;
        b=cjdNaT9KxSDbOFTtp4J299RZWpnpmy4OiVelnokzF5cdOXCLwFDQQDhdrj3Ch5O+Dd
         Q4sF1LvsNdg2CopIKpiK3d784W9/uHE23KGLgUhk0My+v4RJP1B24VRKZT/p0XVxLwSs
         5p4Vicnq+iLS+txlAP3V23+w9ggiUPJp59A9mzedssUgcC0LvQ3oPHXd7RayFTOo1/EI
         qW8ssyR/55Ghc0cELVu1Dt1NJrIvPlXIQVBwzHCWtMDYdv6V6Rt88PAUhSkkioXseiNR
         3iVn6TQQwvwcB8Za0QcGqDiC8n1Ja3MQt2rIhey+Zbw0K/ZWlhVHUedc8aG0YIBfgphX
         XzKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Kz0fzd+4tyRwJHajfPmubk9V6sZv2EKiKfL/KU0Hmq8=;
        b=f/KVYO6kEsKafdNHsUGEqCiAr4aBpNUB/2GxKSVGH/AktEUgLZTfnABd2p86ZIJ2pp
         uh8kAPfjzmYa4HwHpQaERZ58UrOtrmBXpMVvKWB6WljenvucFoT9urei45u0ruPd4UT/
         QvpoZwGPCq8j89KStqJoDs1MnvsB8d8jjaCUhaLp9nwgPb0DcqOksIzAfWnHqGfek5tX
         ELllgr3HNVaReNvpgauRZubKsBkfXB9Xu73BiamfbyIgYlkC1eKhFWnfwSdFiuWjuLss
         suOuG7PEuWMCXc6Bz1BNZ5EKZ0pSDKcqthkin/wLKZ97sBGsTpjU3H0bpQtmxjCOs4xS
         gaFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJGZNvjr;
       spf=pass (google.com: domain of 3uftlyaukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uFtLYAUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Kz0fzd+4tyRwJHajfPmubk9V6sZv2EKiKfL/KU0Hmq8=;
        b=bQowwmdzOnr6w/6QI0OeVM0FWYYpcnMGzAqo3cHYd524gzGS3zBOKDU7+QWUlkLLv7
         mx1SVRGJJ6COQXDMwVr+EQvPZ3gJHL4Fs5tqkcg7lggvNBbXkNlfl1i9oOWfEan4GbuQ
         1Om4DwAT3EjsYaTGQRSwURQAKFoYz36nJIsrOBzJbH1kQHP2hQ5TDB8iBflQqARFE4to
         U/Xc5lBcF6D9t5zTX+ebKmCntlLw7vfATNS/Pd7Hxm8RR4tAfYTG7lN44gH0igyjmJ6E
         uZIGW1ExqBUJS7jD4FuzgoWSIJx5BqgNw7kUaIwzvKKgOYM0hReFNEWQubma6t1udmUa
         fq1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kz0fzd+4tyRwJHajfPmubk9V6sZv2EKiKfL/KU0Hmq8=;
        b=W6hPIgHfL01BzqquvhLdmnt8bc+gYAPyybsWD51iDDYhLzANVNXMu8PiZX/U/ooDcK
         jJQNHdKyonDu7j39+jK749TrR/LTCZTpZOy9BmcMu83rVPEIfvLbirVPhwxh+R+aFhU8
         QmTIbD6UhUJ+VrhSCQUmUY9F+i0Qi9iRpCd6IMw8JwHFnhWGz4YGcJJYFqd3o3mNqW1D
         jMqH9mDMJQOEr4JdWunMbDs+ee1dCv8qYpaR6vjACdgU4rgMRNsoG9Rs/z7H70e12g7X
         M/0+2XIq3sMcHEFfdpEdge8abwmsK7/5yZ/qakXP9Q16ERDrTTsPuJ3avj5jHbMU5JeZ
         5PEQ==
X-Gm-Message-State: AOAM5318Mf5EeWprYKOzyWKuXoI1EfZW1OwiLpLOyR9HLlMweKoW6+5o
	vkXo/D6KX+230RDFFvBJR3M=
X-Google-Smtp-Source: ABdhPJyzjVR9tw4GP4PQVNYKNzJ+4kkpd3NHvTAU8jvu6SH08FvWXFGIgFANC7Mry2mAiqsX2RtwbQ==
X-Received: by 2002:a37:6616:: with SMTP id a22mr11833023qkc.419.1615551417231;
        Fri, 12 Mar 2021 04:16:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7497:: with SMTP id v23ls3386032qtq.5.gmail; Fri, 12 Mar
 2021 04:16:56 -0800 (PST)
X-Received: by 2002:aed:20a8:: with SMTP id 37mr11145814qtb.170.1615551416781;
        Fri, 12 Mar 2021 04:16:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615551416; cv=none;
        d=google.com; s=arc-20160816;
        b=E5o2Ym51GzrFey3CrGGVs1wp1ty3y21FwGcqty68SqpwffwsAwXYx/C249enHQRZVM
         zpMaJDSKokXxcNMK/jLb9xoKhOEBmDlBYlIfRmLfmVNySrtVxb0ixPBIi8Cy3a0gVBOp
         YvRm+w2nclV1bxxIHYW0tE/rlJMuy6o03aoL0oRBIFr2rstAONHU49tMaBSGBgEaW+d3
         WgqZGcSKNBATUnMdmzVCcLDPTelPCu2RfuLBFz6P2kruU1ITRNTWUCjL2QZd7KolM4pb
         LbuSrNBlvpLGnUWHWBYD2kzhXiv7Ya3XtTIou0Hy2l/EmQAmaJ0KYgfOMprXZpxBTbCj
         tcCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=lKkSFyfUt4v/K1TZ3S0RPtMBMYYMM41WrxOgRZxr+i0=;
        b=PMRJjWWy7pfGK/ttOhdHYQNdEMO8EFPNJ5obG3aWPnZS57QvWY8xUxwmCcz5QaNyk3
         AUcNEYDhE9legVk4I3pnfdZlt/+X91/CPEivQhUSP5aOzsVwAHMnKCspArqtGGOZ9kBP
         ZSBwdSuLGPHkk0aTUXcWOQOiVIYnJ4ykPrLHep8zNwubFxzSsaZCgrzRzurls8Jb7mkd
         y3XJiLj0TwLVvjI9flLchEaK7ZasWkGSOZavRUqqkh6OqN8/5sCCiz5o12fZxStTCp3D
         6H4AP3iw3mrVHDT7mE7iUStrYjY7aSFQdTLAFrEuIcxW02op1DbZQyB/D7ANgoWZlT2F
         5SDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJGZNvjr;
       spf=pass (google.com: domain of 3uftlyaukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uFtLYAUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f10si257552qko.5.2021.03.12.04.16.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 04:16:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uftlyaukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id u17so17409777qvq.23
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 04:16:56 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
 (user=elver job=sendgmr) by 2002:a05:6214:80a:: with SMTP id
 df10mr12249434qvb.46.1615551416493; Fri, 12 Mar 2021 04:16:56 -0800 (PST)
Date: Fri, 12 Mar 2021 13:16:53 +0100
Message-Id: <20210312121653.348518-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH mm] kfence: zero guard page after out-of-bounds access
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gJGZNvjr;       spf=pass
 (google.com: domain of 3uftlyaukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uFtLYAUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

After an out-of-bounds accesses, zero the guard page before
re-protecting in kfence_guarded_free(). On one hand this helps make the
failure mode of subsequent out-of-bounds accesses more deterministic,
but could also prevent certain information leaks.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3b8ec938470a..f7106f28443d 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -371,6 +371,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 
 	/* Restore page protection if there was an OOB access. */
 	if (meta->unprotected_page) {
+		memzero_explicit((void *)ALIGN_DOWN(meta->unprotected_page, PAGE_SIZE), PAGE_SIZE);
 		kfence_protect(meta->unprotected_page);
 		meta->unprotected_page = 0;
 	}
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312121653.348518-1-elver%40google.com.
