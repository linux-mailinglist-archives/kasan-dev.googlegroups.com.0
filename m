Return-Path: <kasan-dev+bncBC24VNFHTMIBBWUVVSDAMGQETVJVKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B193AAEF9
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:42:04 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id b23-20020a17090ae397b0290163949acb4dsf4194243pjz.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 01:42:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623919323; cv=pass;
        d=google.com; s=arc-20160816;
        b=C8JqoGGO3QDpuKdlG0jhvz9IiWKtaRIr/ivt+M5EFOSs4DFya66+tFLXqX+oMp28Hf
         +A/wnfy6VQiKXlxFUjZZZoQY4ER1Sh2AeL8Tg7qy86aro41zZQVfzzPHigzMRIGcLo8Z
         eNZljGdFQ/Gu1dIhKCcyXR5CpVszP/fGSTFkhU53yDL3uA1I4vgutVSiAzTs2AwAktjS
         QFP7PdZ3xFfdquL9SGIBnEWOuP1zLgA/9GbQAa+B0ooMP/ejQfLLrGzg8qMbfpEOfJys
         dpdDM2gIm1QNzrQN7wNX37ZUC5YFriWLeG2/5VqM1lO7XGEAa3BLDFV2o30VcuvwPkjP
         Xaug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vOrwwFvrgQbVIMZmP1bMHmtVgMgkr0BqpgpHPAPj7Nk=;
        b=TIr/wa3UNoleN7YziUoczkb86SEKbeWuOVs6xyF3vQgZTDt9oe4KBnLNGvqRKAOmrl
         zUUKCAZStAAgrPFDmdUcdQr0VievGeu7fjTi8QSZSyhG4A4A9ZYLe4XMUNuyC0K5qDNW
         9xmZHuPtHklF0v2000VfQNGGSIp/xDDP92ziVF9SrDs4W9z0XPSUR5F55Y18q39qHh8w
         TzK1YitQ4JD+8aJwP9UACnqncE9cS0sACqpcKZKWepyp+Po42hjuy7lMV1tPDGRA3JGh
         oXJmc7tM8Cq1PUPCgLSpwgiDBS8HHVVTGD3as2+SIqyW2kTR6jvHqsVQmOjjEPheBAIm
         AnSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AezBbAFQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vOrwwFvrgQbVIMZmP1bMHmtVgMgkr0BqpgpHPAPj7Nk=;
        b=izhINQkdDCZf7tFOIVJzS1fAdLxhTD4kIF3Y/o3oVI/XroPyReYBc0BXDTfe0LE4Om
         BI7VE8VzCTc2pE3CtmgklcoF07I6hxX4yx4Zo57Vi7o+V2ZV4c8Y9vT/NVPtcM7LMFtH
         pix+r1Fdqobq8CSJ2/8RotdXk212JY/jEgwCc81TypECVZeGNXGJLgg6C9PiodUjQgPO
         xIlbXCuzgdzQOZXIGqGk/owUlNHirf6KKNxUzF00D7Jm6PvQs4gVyV+FV2yBFiM/0ri3
         K4s7SjbbFw77bG3OcUwUj8u/73u2nc8Xw2t0cNpkVB8R7mnkzrtQRdJKQ/vC5XCcB3yL
         fCqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vOrwwFvrgQbVIMZmP1bMHmtVgMgkr0BqpgpHPAPj7Nk=;
        b=qSPbDlmvclbkMIRut5v1tLAK98n+4QDegBMfxc4CYEWo5s1hBlQonM7CkhxmaGrWof
         Z59IMA+PHh6CBBxjuO0uPU7krFkOWeLOLe/f63IhZEUfmxzMFWX2hb5d4ATHfR2vFEZk
         8seFSL7v0XOgbUjHEv5PDjg0GB5gUXKsFd6lS4z12loDVbArggxtk0QQhXMWsC1YKN69
         ovOxBx4jxif79JxOIMimxOq5exE5S70BJAAQxW+WCSvt5ImGlHVHA4RrJZMFDXcaJgQZ
         69rtCzC1da8m5EJFEeca8EoLif6cIRf6A/j3cXhiZMCVZDTqpX7r9oLiR87tTD5yixrD
         u1AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hX9BNlo1cdWZMbFhaIFG44dkHaEFwQQKxoxgugQU6IPjNL8kX
	s3+pFfoLdIobJQ2nyVhTKaI=
X-Google-Smtp-Source: ABdhPJxZBhlhMXcqwUfNYfC1ivIqA2o/RWiThxNJ9chjdEDzSn8PuxhzWK7uIHkgcoXcxaLNGA+XFg==
X-Received: by 2002:a17:90a:fa95:: with SMTP id cu21mr15989686pjb.210.1623919322906;
        Thu, 17 Jun 2021 01:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e23:: with SMTP id d35ls988270pgl.5.gmail; Thu, 17 Jun
 2021 01:42:02 -0700 (PDT)
X-Received: by 2002:a63:2484:: with SMTP id k126mr3889445pgk.1.1623919322364;
        Thu, 17 Jun 2021 01:42:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623919322; cv=none;
        d=google.com; s=arc-20160816;
        b=iUoMIl/k1ZhAbxog5r47aiXk6qEjenCKqK2hj/1Ic8CM6HCVvKiHlj0CrWatYo6xMG
         APazT1jo7iPQ6+gH+VD0WW6nlHjNuBfyzDcd31eG6BSrdQFUaTkj0K0umPwgrjVysS0A
         TFUW8OH12HkU8QEHdp0jQUfp+UoVRUKK8VMiBNb8Cgd3fofDMhi9IMPdy19tj1xom+ki
         F2mKEQOg+AOoaGH9LkCJ0sUMpLNmR5NxnS1FZhNLVsVcRxWzlTRNn1gp3b4rxtKC45Qs
         b5VykllgcFogasNjtPTLrOrWck2KXzTHD5KVzRi+VHSZSkx4L2vun1IW9i5OfBpcV9YJ
         67Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ufdvcdLdqGSPOIKvHmbhatnOvzel6M6b2oryorilhcE=;
        b=rhKF2H2zYPqZmnTAyPVtFMuf3v+ealIfOu9TvvOs6QZtSoGoRPwuHIWwNXp+IW5Bdv
         5aGzWdEIfenVEol6xqlDQyOMQT5U150F0xzlxCymtkFysyUv6+n3YzFD8SeHj6/Bph6a
         DyWFtL1bCa5fwSGj7zkQr5EGmBB77dPkwuUP7ZT+tdCsFMv3XqDb/0Z2NvYw+eN//blg
         tAu9Rct5ZgjyMe/l7jXypL30NmkSLu8z3A26Tsvao1IE47OPYcpRO3F1XXmM7RixjJN0
         75sr13iwhpVl7eyeCw06vlTD7q+1Fbxc9IOBd8kUoBuydvsnpQojzhXO5f94cKbRmbEA
         ydiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AezBbAFQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mh11si634967pjb.3.2021.06.17.01.42.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Jun 2021 01:42:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 043C06135C
	for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 08:42:02 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id EE55861165; Thu, 17 Jun 2021 08:42:01 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Thu, 17 Jun 2021 08:42:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dja@axtens.net
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-213335-199747-GGpyhUlNqD@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AezBbAFQ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213335

--- Comment #5 from Daniel Axtens (dja@axtens.net) ---
See https://lore.kernel.org/linux-mm/20210617081330.98629-1-dja@axtens.net/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-GGpyhUlNqD%40https.bugzilla.kernel.org/.
