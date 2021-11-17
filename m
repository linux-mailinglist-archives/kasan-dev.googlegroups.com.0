Return-Path: <kasan-dev+bncBC24VNFHTMIBBTWG2OGAMGQEL7M752Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A641454566
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 12:11:11 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id q3-20020a056122116300b002faa0b9026fsf1133014vko.18
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637147470; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBW9DG6cLSy+399O/pXexgkSG3o2nJ7uA63tXpQdpIiAZL7g4QLylXkl6Rs1LZ1AuY
         nqnGA7PNofH4f0YGVBzjKGq6wO1JHbDbBugBRrtyRmXdPk0Yf4OtzEU+lRbEP5FMkOYE
         vIC8ALAd5qDOWIUCq8bdlIydKUfss8H1PHTeX/Cygzcje7dkW4dcfTvnI7a56gglpfWN
         kAna3JHbqPRu+04+Y1rishkIIBSEpjpqjKbDS+t2Miz1IJdiJSPCLNdWrkrl3UiswQZP
         9fZNSGgL3VaGrnj6WU4IhhUTBYsIINMHYzfkl2pec8ftFQJkHaJvFCYhkpWQwvgt7+gM
         Em+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=TJMyMF4JzhBa3lDumT3VPMtaxOdFyPRRjba/IllxNFc=;
        b=eHbD7185HA49xaKoAGC346nNyYrf5HE3FwynbI3Pw5f9M/Ajvi/CWS4/FKqxAqouYM
         sCuoIpzmLCoht7BhRWL2k0efvPHpi9FF9Wj/0dNkNmfoKn5zwK9rqUFAsqPfSPlaDfGz
         jybU21Pvgimm9CJm0LNdzU2xy5sVtoN4lVRLqF6G8tGos0/YlXxVMzSbEzWKgh9RU+gt
         Ca+HOJqtjA4UqjfB5kgjHlUcuvh+gydIUMglOoLVMh/vNE1Xtm6BjJU/mhpc9ZXQmRq3
         yBoOZnkTqR6Yy8QurjAsXfq9ESiWfB0wJGKjfvVOEVeU2Jo+Uc/F394l8gxJRsNHt6JV
         HllQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BowKHVxE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJMyMF4JzhBa3lDumT3VPMtaxOdFyPRRjba/IllxNFc=;
        b=qB7lJC4a1KY+dETJLt1Qt4MvDp+FFWxesTdbNMeoqrBaDRYiE4lHnfj3lvXVqtOvxc
         wjJLW4WaRxXJOzguVGgAF7mZC85xJbm2Xk0lzwod5tsVvadMq6nOkaaSTuSbYcv8nsQ8
         0Ce5hTan7lluZ4Sl7PVFFIhAGAyMfM9v6X/TA6LFP0iRuxai+EmTenDzDcLmWWfJJ8j9
         0Ingv0HXqF+causnyRxKbmmZvVI0H89PoV6kd7PUqar8Evs9dluQFyVKCGu0G6avWynn
         2o4wbj4DvLvsqGVEbQlof/cEJATgwbFXaoMzRfY+x6m/yVTq9LjuhVePNhvFwuT6AZfS
         Ynrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJMyMF4JzhBa3lDumT3VPMtaxOdFyPRRjba/IllxNFc=;
        b=Q4wsR23ZyVCU6s4QjfOiQcOKxDmfB1M8LaTBeZc2vccFmuyfXmwxkbmlRb9HPPhF/7
         BJ02zU94IkEg0cVJNATNOKFyIbTZaQmv2qAgayI7x0b778rjZM9rTi7tPxVKV8ygsqll
         rSPK4gjYVftt4J4ksl7aOZwoN6ySIfPPqNa5wRtTxwwgpt9D0L0dpB1lAI+wzIG265GL
         aqukC3rbn6aIFRvr0jkWJZmYgwzDBmZuDQPFPOfkWXwr2MPsvqDX1upWuoLXs6OQ+dW2
         iabFprkZSdZxnHJknTbAhqQmYAd1rqBPmDFah76h99Uz3Zkrb1fzNvKWIHWuSd0HkMQ9
         ltLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53377tIb2+ReDNoSVoGoW9hADyHgK8Nw7RAAzoax876V4FpeMPIJ
	B1deJIHm2TOMuVRNh+WG/po=
X-Google-Smtp-Source: ABdhPJye3Nz3sKb2w1KBBxpHtsq1s6m5JHOwvZsUpxMHmI9VJTKQRvVs+uOsApk6iEHYsg4quSFWqA==
X-Received: by 2002:a67:df96:: with SMTP id x22mr67393880vsk.9.1637147470207;
        Wed, 17 Nov 2021 03:11:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e217:: with SMTP id g23ls2894289vsa.0.gmail; Wed, 17 Nov
 2021 03:11:09 -0800 (PST)
X-Received: by 2002:a05:6102:c86:: with SMTP id f6mr68317774vst.38.1637147469772;
        Wed, 17 Nov 2021 03:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637147469; cv=none;
        d=google.com; s=arc-20160816;
        b=UMwyfXBmq46Dee+e2854SWeCiqTXHj7fXhDB1oShM0ijQ1MpgIuCj7f4hB7QtE4uJo
         mZDpE39Zd8uthE8oszOEeyF2+W1E6LqdPMXKJn2DD72xJbjLQsa1WSjhAbCGqiT0qgk6
         e9upexqWGdmBM5xrlO08CVDtIlz22HlcwxkpprCm0aHVpW/x9NnFl9KS4gxlQhzty7/y
         O5y9QQUnZ3c8nr92Tom2K2Y4svxnfvPqCkiULITvnPrB+VxjPj1425WzGlaNnci+NdxT
         t47FtOkN4a7YLtA4SE6Tm4HIVYw1k6d4IfRBl0u7EbGnDgIPyhHKtSbnrzkoZeWgArbT
         Jl/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=gRY5HnyghA45SXdiQF04Ax+ux5pNkS7ZdGXRY5QOoG0=;
        b=G5k7GyYd8NUCY624nPtNBIaBRTiggJxxF3ByNOc66guXR471s8f4gD/qU8FH/X/PwZ
         aR07afACaj5PwC8LKS5WfHKvnMtDoDtfjek3nb+IkfQTfRVzc9xvcD+huWEHEiiJV/xl
         xrqwsIoDPcStiHTkGfW0S/ZVKGIQH6tBpmRxQ+JHNzAcY2ITwiL/8oVaGIUzCqyNAwf/
         +J7s3wZ4kNMvSSeQCHOcqAosAiTWeteinsFiWBXPXNzaZnmPE59cCeqPFvqzr0pMStu6
         72GKelxK2GgaJITbjVYmOh61VP6hRNUb2NkFWH63t03d2tJqUkcWEmKA0AiWhQtxS0gj
         cQfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BowKHVxE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g8si1267720vsk.0.2021.11.17.03.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Nov 2021 03:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 8CCA6610D1
	for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 11:11:08 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 7F5E360F23; Wed, 17 Nov 2021 11:11:08 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215051] New: KASAN (generic): gcc does not reliably detect
 globals left-out-of-bounds accesses
Date: Wed, 17 Nov 2021 11:11:08 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-215051-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BowKHVxE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215051

            Bug ID: 215051
           Summary: KASAN (generic): gcc does not reliably detect globals
                    left-out-of-bounds accesses
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.15
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: melver@kernel.org
                CC: kasan-dev@googlegroups.com
        Regression: No

GCC does not appear to detect left-out-of-bounds accesses. We think it is a
compiler issue, given that clang (11+) can detect left-out-of-bounds in
test_kasan: https://lkml.kernel.org/r/20211117110916.97944-1-elver@google.com

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215051-199747%40https.bugzilla.kernel.org/.
