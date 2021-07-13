Return-Path: <kasan-dev+bncBC24VNFHTMIBBFFJW6DQMGQEPXEGVWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A4AF3C760B
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 19:59:50 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id 124-20020a6217820000b02902feebfd791esf15827330pfx.19
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 10:59:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626199188; cv=pass;
        d=google.com; s=arc-20160816;
        b=y3i6AUuDz4row82EXLaM6XI4Jf8yvxWA235WTezk0fklU0BqJBTjb5k6UBhI7CLfO1
         Fa+mI4t9grBnkZXCG5t0nPPf31eQw64MfHK3GUg09x8sGP2m/aRNRr5TnMiPCHfK1AM6
         ta+OQ+zxwLucC9YJftRty2ZvaUwPHFHKR2xML8DJiMrNFhFYhxwaVApR96qjYBxBYwtE
         Nk4WqW2uyE0UmONwv0bdo2i/PDxB8mPWNlOnP0yjeMZOFBwVKxtrxubltc3E4Eh2ajZc
         qOBOggzMe7MI4I0WuNDz15fXrqHNoPjFUwgHYqODhGl9N7EIm0vXPmq0VJjAm+sGNruf
         2GmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=aBOF6txuYjRY6L7LinVVZe2f403jE5ruv2evIqqPOSc=;
        b=GS1XigsRFXXGqlfmuC2+jjeUaviQ06FL6vorA3OdF0G0/5NpE2QRFZfjjsxpe44DhY
         wedohNizajVJzjYztM/mk55aUCmB8+dKft25ZnT+ZkM4F4XYmLmsgq1rDyfw7uXHK+EZ
         YhWKUhP4HsKyTWKTmwDiWYojElZ0i5/oXgsy9lSlNTnvA+u5zObO9tVytygGq8eM1dFA
         nOcOh6lW9rFhWY5HFt00Jo95l4prQ+kGUvL1eJ+sbEoNQPMdy0Sxhhrw42j52VXJbCHO
         4HsDuro1GdoejSfYzrEeo89P9EcUPDYhU+8CT9gGtKVZz0WPhlqf4CgGej4DWIPTJEuN
         Z+Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cGge74IM;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aBOF6txuYjRY6L7LinVVZe2f403jE5ruv2evIqqPOSc=;
        b=pC+df8TX6Ax4hDF0sG73j/vY7p+ejeWvvdBHZPZzw59myJlEkxxh2aSIHn1NOX7NAe
         UNK7miUthlYibOxoAqqmbb22ud7TtEysyjpbhWsXl8uW5Z9gb2IqOCvzUZlH/aTrsEXG
         CqU6qCvwxV2ggcHOd6igqrNutIf85wdj+at2GiOE8L8w4rrIf55R87qhbLsv+9+1sG4c
         Q3+DhwJFry0NhNL1sufkmQcLyvYksMTJlSk6mUVDQONw03zKiMMfTgpIXZWyYlatFVru
         U/xNcWuo9LfiBv4RPdU/xMxJ1SC5jTKmb/vmPQ4IANWMvXlposHCXU4/yHKpBoPn17BB
         Pqeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aBOF6txuYjRY6L7LinVVZe2f403jE5ruv2evIqqPOSc=;
        b=jooK10klVK+I5tMPCreMnC4oI2ndUniJ+i58Gkh20QmMdrmWDG4mSwTFIn1KpB3twE
         ez7AIDc3lRUKu1SvFOetOSdb6nf+3vLDgZyIpkZB+b7HwDpZi1f/oJrLQ/U4jq/rYLIA
         cJulkcbpbi+TwI9jcrtILlUvfhSO2CYlcCF61fNESzsFJ6s85iJWtL51OUGfHIkKnbkN
         cnJkp6I/SKKQoIo37EyzGzcZo56cm12xkQGgI115gXZJsh2C1vVLUO+OVCfNZPD8a7zv
         wAdpVWgJ7aSk39qmmVKz3jH5WgU0b8zqhIrj+ziuQJfWljLgNWKsDEJ31U1H8iGhPtim
         KE3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WY685VKPV/wnacoRGwtzIqfxcuoYzyqEFuXkR0fFvJYzqicXZ
	KgrSHSZwTGJlCAUWHBt/bKc=
X-Google-Smtp-Source: ABdhPJw6Dc6bCrngfVR9UcYSdiXLD8RkOYUa1cZcDPQMJNFvezqdakdqTMe0jHvN4nVX1jdUmT4RSA==
X-Received: by 2002:aa7:8812:0:b029:32d:8252:fd0 with SMTP id c18-20020aa788120000b029032d82520fd0mr5760898pfo.48.1626199188781;
        Tue, 13 Jul 2021 10:59:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4283:: with SMTP id j3ls9481621pgp.11.gmail; Tue, 13 Jul
 2021 10:59:48 -0700 (PDT)
X-Received: by 2002:a63:f40e:: with SMTP id g14mr5381487pgi.158.1626199188263;
        Tue, 13 Jul 2021 10:59:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626199188; cv=none;
        d=google.com; s=arc-20160816;
        b=ese6k6l3q91gfcTICUlo7dco/E7QUn9CGJyVqob1WB6BGChjkTibyIG/mZEkpMILaN
         fX+ZTEgFtI0y9t7hX7dda1F9K5HC1XU7fDElj2+EbztX8OYte+t1FPJmw3SIMxKjdBhQ
         Iqhn/9x/8o1+jzyvxm/evmCALEPuLr6uHobB9xTQKnjcfMrRwEn86Sj+v37rhqawxKze
         MzdJyDsMTLq1YplBNfkiUvIx4QU4NMMDoMDKKYdfuBZFsDzN3IldeEoNKvLQl9iHJXfX
         /eaQ4W+g/QB81a2KWDwXOL7cvqScIRoj/Zpv90FEjKi3Rxr+hBTcck43hjzWfEg55COm
         bhcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=MbDOq5NSmQL6uFOOJ8zgvOTaVW24bLSEOFLoEPViM9g=;
        b=vi6AVys5w3RXI3SqzGt8qDQKo5vVP2jXSw8mXXnqdR5KNAHkRpHdBXc+i7xVldvmg2
         vVxwT1Z6fwz3v58gTEIB/LLHscIkImcNOrZ9lAiHl2knPkTQJqwlyQ0edo6vryrH1J1x
         VxOZ88KJW8iJCw+oRisLJR0Qlnrx/FRXIz5LPLZSU0nNkWz3KxO2chkhA8LteDs+l9kF
         1Dk2oIg6/zkEkkyxi00A8dlijxvkYEUTz2fD4VtyltVPJS9lE0OtngOHFdLWJXk1D6Pj
         1rwG9a8b9lChju+cKT4NSa5ETtWSzHuFA0dLSMlBSALXfZvQ6iw5eoVKyZvFBsmDFXSF
         g7zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cGge74IM;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q7si2555038pgf.3.2021.07.13.10.59.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Jul 2021 10:59:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id F13C161361
	for <kasan-dev@googlegroups.com>; Tue, 13 Jul 2021 17:59:47 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E725C6124C; Tue, 13 Jul 2021 17:59:47 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213719] New: KASAN: don't corrupt memory in tests
Date: Tue, 13 Jul 2021 17:59:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression attachments.created
Message-ID: <bug-213719-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cGge74IM;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=213719

            Bug ID: 213719
           Summary: KASAN: don't corrupt memory in tests
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 297829
  --> https://bugzilla.kernel.org/attachment.cgi?id=297829&action=edit
kasan: don't do invalid writes in tests

Currently, some of KASAN tests do out-of-bounds of use-after-free writes. As
KASAN doesn't suppress invalid memory accesses, they can lead to kernel crashes
while executing tests.

We should rework the tests to avoid making write accesses outside of redzones
and alignment areas.

A draft fix is attached. The draft addresses the tests that I observed
corrupting memory in my setup, but there are more tests to be fixed.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213719-199747%40https.bugzilla.kernel.org/.
