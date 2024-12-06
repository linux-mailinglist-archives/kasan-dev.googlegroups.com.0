Return-Path: <kasan-dev+bncBAABBFOFZK5AMGQEEQIQVXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 139929E6792
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2024 08:07:03 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-29e56b740efsf464651fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2024 23:07:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733468821; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hc1eV1pB7FFrl4VTvr8Q5jjwPN38tep7Drum22VOgGWBA8vTrpWYNXYSS8FmOlD0hl
         yxf94AEpNmgXdu5GFlpM4byF0bLKj+8SilcLQFpyHOC8RQi1GzohZmhyY1V5ZWOyxzIX
         7DqW/DU4QyJWC0gANxNy3s37nGSCscSehfHaKLvQCrbdvTlFPBMOlh+9yyGOByO3Hqzq
         ZDfkh2RtaF/kNYxOhuUxx9Y365eJ3i1TEx6RGosuRSzVx0dR3o95JwM9zAp1rwKQSuEF
         jT03AytYUrBf/gCUs7dfl5v2BXvGybEeg99HTGWQVYWYjEronm5OE9fEyDoA0BL9cFYC
         IulQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=vg4D4duj8VSXTMMHJM0ErXNSEOMKZ+yCL3Tbsu2EJXQ=;
        fh=toa6Y/FA1iXkjuMfqm7hJ0eYc45qOvgMj5Iuoeju6+8=;
        b=e4LjiVbAPhsspZxZ1kRmlt8aUsA693i5NlOFGwqeHWQXldAavFbxjaDEo45KjyVP0F
         C5PoYel4s/YdRBM5mObkZadufywevcHC5QeGA7mzwjvaoi4WCJn7cf9wvEbi8Lj19+n1
         Dgmzq3RDE7YClRsgmsmdYETnO8LByIrEH1TCQ4BtjjrU+9YdGqluP6oelB9kHAQIKp9R
         fBDI6xxC8V6eD8VR1sSI3COpKzvU+agTA7h1DhtQM0PbNqUrxZ29ow0HjROvRyKh6t2W
         dhApvTWXh1qBB92SVt1xQOCJyVKOEFk7Z+un0pU4TuqQ2sU0J3eOGTbScPr3VrJhVwXi
         ONgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NVmwtC+x;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733468821; x=1734073621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=vg4D4duj8VSXTMMHJM0ErXNSEOMKZ+yCL3Tbsu2EJXQ=;
        b=fQm5f0KY/PPf0Z9Kkzh8Ewty6sqgdp8rUKCbRPqzHUjbeuaEmVabgQP5pqOd71f2Rn
         fGJsKdHfzkwYETD5pgyxxHeF4smGvt9DGYr2PzbdZrsFYTV3qlkrpjV7dpmKo+QxjrGt
         knLybCwCdRqGGmS0qaVouqjgVOYE923Suww2TslMsFp1Pvfveajn3ZvehOnziOV+uXL7
         wuhqsW7WsPzdfLV8vmMzqfI/uTWERCU/UGfhN+XGV5AxSZ26uQB43Ys0J//uDgFHd3jI
         atWJsEPy0xgWttrST6nKtHuqhgb0NciVXgcw3J7dQaqb7fjdSVFyXBshFXhVa7+RHPah
         EROA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733468821; x=1734073621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vg4D4duj8VSXTMMHJM0ErXNSEOMKZ+yCL3Tbsu2EJXQ=;
        b=eHhRMGOX/5/3+fdH+n/zkbPTBmtcWzVVXsYvanfuNCiO43tQVouJR057Tat/5L82Zo
         OAHB30xpXKyWaycklfI8cUqEF71/2k1TQnl02TunX/z92qvbWY3yrEim5dGpKWPebvot
         1r/xuSPfc91UKvN0JIsh9uqB/QKTQYy3opWMd0/ScJVj8CnTxnumHHGFYouDnQoA3QHO
         /U6S5C7xb7v7c4zz8A5m9ClLtpZZU5gBwEhbwAFtXO5mexMKl3DYwg/91UBA4kYr72Fy
         UTxigN1onUGGMG34nnDLH5kc82GWXkZGXrhRvas+c/44UEe1puMhmo284927DJC2H3ly
         7CdQ==
X-Forwarded-Encrypted: i=2; AJvYcCXydbNeidvXls6OKdcw10qNFK9XgWqX/JOhC+GLlj4svZjcqU+wLP+DJgPzxsQzDq/wacQOEQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx85stuc279wb4sfWZIvGquoehOTKlV2hR8WFvaEKHaJcJgLzov
	1k9+wgeKhBekbNzh0jN+CV1Ij8swNjNnSGF60qUltq22Yfpus4wp
X-Google-Smtp-Source: AGHT+IGzaI2QuGmrRy7dwx1yL8RpT5sP1LmRlFwCo8k5skvmxXNAQJ3SXNZ+oW4T0phsAk1xCbrrDg==
X-Received: by 2002:a05:6870:de18:b0:29e:5df2:3e50 with SMTP id 586e51a60fabf-29f7327d68fmr1136480fac.15.1733468821574;
        Thu, 05 Dec 2024 23:07:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1716:b0:29e:5db3:adb with SMTP id
 586e51a60fabf-29f4ffae398ls77121fac.2.-pod-prod-06-us; Thu, 05 Dec 2024
 23:07:01 -0800 (PST)
X-Received: by 2002:a05:6870:d91b:b0:296:aef8:fe9a with SMTP id 586e51a60fabf-29f731ba859mr1107045fac.7.1733468820908;
        Thu, 05 Dec 2024 23:07:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733468820; cv=none;
        d=google.com; s=arc-20240605;
        b=YyzK/2ZX0U+/qApwuKx/RHYZYmUBgO9nRmT87lDkQx/2dHG2r8BbPtvqSIi0kaJFmk
         Y4AOao94f3+ggdhdPOtUnjlyeYzy3zk8THBgIeZ0IO6qDup+yxMDGD9ZqzfYI6VAmvug
         uLAf0ljRlqU4lhtSMwObQms1NTHKJIT7XMq2ur6r4RNLeGOqXEDwkQgXH1o90ZtghlOl
         MfaTSauRhb/KjlHVDF5FPAs4lKufiaM7kXgo29A8UYihtqO5+/qh28NHj7pE/uDer8eQ
         hdNsvm+Q129GwyvXqvNNRaQf1OwyAebZiO/500RnQeL10PldpfSl19+B4OhZsa7oXeSm
         3zvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=d6OJW44Pf0MHecZcD8t2bdI+kK3boz1hBGoFRZljd+o=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=glFITyKbv2Cb78snDeZst/hu1WMpiAKOsAPM/SvnssaBhtSw6jGq68TV3KEnDUANdL
         KjRRKrwZrGmGd7VeBSWYeW2ajYyecjkzmRZAOoNd7PKhd0gtYrL9lpC8fyIPWprcezjH
         jVVELJBbiJpwTPF70LmaZq4mz0iJQm5JcytwK7XoUe+6lsugV2KjE6Y7bnJehA/TZnM1
         2W0JsCI3+Qu3jcPniM34FxlPcLYREFIbXvYNKG1liDPdiZH6zk1CyYf72jtqa5LKNz50
         9x1cgjoGb6C90Z4HuUEbatB0mevSdHQNuGNQWXBi0/foZWmIvU0npHP2292fPnExP0DX
         Wx1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NVmwtC+x;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-29f566f8ffdsi148229fac.2.2024.12.05.23.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2024 23:07:00 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DB1B65C738F
	for <kasan-dev@googlegroups.com>; Fri,  6 Dec 2024 07:06:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5E551C4CEDF
	for <kasan-dev@googlegroups.com>; Fri,  6 Dec 2024 07:07:00 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 50BBFC41606; Fri,  6 Dec 2024 07:07:00 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Fri, 06 Dec 2024 07:07:00 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198661-199747-qvolcj3nin@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NVmwtC+x;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

--- Comment #7 from Dmitry Vyukov (dvyukov@google.com) ---
The patch also implements detection of duplicated syncs, which may be a
performance issue.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-qvolcj3nin%40https.bugzilla.kernel.org/.
