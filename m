Return-Path: <kasan-dev+bncBAABBOVZSWNQMGQETWKFULI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 683BF61A02A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:40:59 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id v13-20020a4a314d000000b0049d5da45bdesf1284963oog.10
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:40:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667587258; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8JA/Y/WCpWu1/NPdeip877uIsSs/3Ox+m0gQC32lFNv/CAUA5J58YGiikx/X6GyeA
         K8LE6vpSkVjwQXAmcZIJ4Dq2WSGvXghtCoHebCdhIuJ3kS/hVePuqaPepi5xeBLygIA8
         1xELfPldUe8qyHopdPhpWZyVB8686PDSfMCv8Vc7gVWcYt9+zBrVrbkoxbmhY4KhwUqB
         rliZ6L2L0UQZoPJn1tFM70KitVk+X7uSiaV81jVSu9aWVjdlnkpjSjwelR3m/0Sq25FF
         U3QvuAeAT/LBME9TiTOQbtAAxoUbKf+jPxXgOgyNy6E63AboKOHFIjSEmaRzgHgQlNrS
         nbFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=x6AsIoKZro9Y4FbQ/evp39XaAXCCNp9iFFq0c6YtX04=;
        b=DmQijCWH2T34p4sQ74GLiROmHl+PiCecn98QeS3PviywyK5zrugCq2+2ba9hGaofeZ
         Euj7ejZIw4l72dcNDW8x7VTFJJBe7khnJju8aRqHfbS/DKfpx09mBWevHZ2gEAgo6mc4
         oCDHXcoaHAH6gXAZadd7LkvbAooPvXVod3vdipyYJsAnEJHQLA2lqfKCeGRMxE/LRttd
         zS/FU1I6Qj1M8sW62RIrKxNs0i85HXwDR42Pvuotsy3P6VL1/DsPPhZTGjHKh/NYsmbH
         hSM68PsTtSwNERq03gKVMrLE2EeDQPeSp8mAVcefV+ZA9cmUylV6UmZNLYpBq9lXF2ev
         yxIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r83TK8GM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x6AsIoKZro9Y4FbQ/evp39XaAXCCNp9iFFq0c6YtX04=;
        b=lbVPv2WUM0V1l//LvoOqMe2SZWmSYYFxwycqTdKJNruPdP5J2BkESSKUkRGTi4Har7
         zz7bhVAiV4znUXr2zSJiw+FRPRw/GOtKc54HM9iZ0N3UIB/hNXoxDjt9upX44st3OBFE
         zo/ozhI/uuwVLlvnkdtFVW7eh0bqy3mty50hu+jTB4caTgM8VJPicUaPgVLjL94CEMbl
         TpjK+sbIxNGaBclhrexCAmwVXOH1piq7a7pQ3VDIDD7HdQJ8TSfKyn8e+6By65DCuzHD
         nzcZZTqFfzosktnUgcSswHboEr5acLIGxlWlq2kFbDk9kQ6RASTZhKtym1RgJkXPLetU
         uNjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x6AsIoKZro9Y4FbQ/evp39XaAXCCNp9iFFq0c6YtX04=;
        b=qU2QIqKqgkHavv0rKk/KQd/nLDAQjrZ2HUkwTaBKTF7SIHvSiEGPUn33atEYZlAcW+
         W1KQxGW5LbOh/Vf1rFq1y8iHV/2C9mNGiQ35D5P9w+0t0pxwW1WONfuISOJC3rukcFej
         j7J+31mVEF7l5sEB+Ih/acevV3Z+DhDsKv8lBLzpTpNLfJS9pchvaumUATwfn3lec16o
         1fc6HUDHyZYMbCeXI7hlzVB9uIe6+oIvNu0yzSzpFZ3DfPWwot89x87ubDs5YnyTomy9
         UhCkRvrZvjyP469vktlbWf+79dIGduSHaoqZdsBS6ILIju2+58yWYLNW9PrGiZ31Y272
         TGfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3X89ogKu5BBTnlHEsEG32aK0QPtLXNoM1OWFJEPJ7j9ZpRnhRJ
	BWyFVtzz8AfaN0Ik+BSqPkk=
X-Google-Smtp-Source: AMsMyM4jwIqanMLsVXjE8Cl0Th8gREljXv8LNOLm6MDLw6jjJGdjB3JnXt6HSmnREzAaOxa44itWyw==
X-Received: by 2002:a05:6830:1295:b0:66c:5617:22b3 with SMTP id z21-20020a056830129500b0066c561722b3mr13349705otp.241.1667587258312;
        Fri, 04 Nov 2022 11:40:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:8c5:b0:345:9a88:c799 with SMTP id
 k5-20020a05680808c500b003459a88c799ls1736082oij.5.-pod-prod-gmail; Fri, 04
 Nov 2022 11:40:58 -0700 (PDT)
X-Received: by 2002:aca:905:0:b0:359:cfa1:ebb1 with SMTP id 5-20020aca0905000000b00359cfa1ebb1mr19383424oij.280.1667587257969;
        Fri, 04 Nov 2022 11:40:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667587257; cv=none;
        d=google.com; s=arc-20160816;
        b=NQWEVhsdO3SJFDSlyRnYeg/80a5Nc+mC0u02rPk/EDo1dR1fV1TFnpfYspYLegQ2if
         CSa8vM17GunUtEa6YsHZRemHGa2s8mX4B6dGFaHey5bO7oAf/DXNHw8UY02EARctTfuf
         2j4i+GqYsJYA3sOyDLe2lEANcpw7yI2/eEFHngVZl+fNHrKGrLLSIb5S4Bc44mOMwdj4
         UGyM4DTTwJGOklcDyBk+l2gmmfYu80w/NkYUVBL53uk+T3aKUnXVE5KT7m8dDGuavNHn
         tsTEzuIegfkgOnG24qud87xwvvFMyVhHDcXIW/37KLdCYOTXU1CushtC8rnn3fIPBfOA
         CHjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4MTHCFHxWalX1loYSqFjv3475pxL/jyHG4Euw5Rm79o=;
        b=diOZgX35IEBPXOzWjfG/A3rLiVYKYPZnGzFCaA6OH2TjiWwfbQEJb9UI1efYTUmcQl
         57cstNZwni96AedrjXQg7W1ZyQR92d/g/iUq10rUfp/ArdZvqZzCWSgetsRU9q15+pLs
         23bNWqMMoi6vxTbvLAX3QGswcicZ115/6h3pCAmA0PRy+VFJo3qSdmPBN0jyQfoGDT24
         qyPqqa+YbpRXkYmndaF8TxTyw2JD/YEON4qcP/3IG+K2oIHFnY4GhZbJ/D9D5bOT2hJt
         wwOnoTiu0oRGKa8BUlz97TJ18x+J9tki+bS15RXMLvxqVAGoCapLNJgfLp0Arzglh4MD
         C78w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r83TK8GM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fq34-20020a0568710b2200b0013191fe1d85si341398oab.0.2022.11.04.11.40.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:40:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B0E6D622FF
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:40:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1D2E9C433C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:40:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0E6B0C433E4; Fri,  4 Nov 2022 18:40:57 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216663] fault injection: add GFP_NOFAULT
Date: Fri, 04 Nov 2022 18:40:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216663-199747-FJ3iZOdLql@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216663-199747@https.bugzilla.kernel.org/>
References: <bug-216663-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=r83TK8GM;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216663

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Reported-by: Jason Gunthorpe <jgg@nvidia.com>
Link: https://lore.kernel.org/all/Y2VT6b%2FAgwddWxYj@nvidia.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216663-199747-FJ3iZOdLql%40https.bugzilla.kernel.org/.
