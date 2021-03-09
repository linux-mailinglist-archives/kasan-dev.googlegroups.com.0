Return-Path: <kasan-dev+bncBC24VNFHTMIBBOONT2BAMGQEQRRTZVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B6DF5332C83
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:47:54 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id q20sf6256764otn.12
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:47:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615308473; cv=pass;
        d=google.com; s=arc-20160816;
        b=NP6h70PaaUds5Xfc+aH/dXgS5uSobUw1MeWFyH2GGb8ljFcTQEIK59kh/inchzxltw
         1YuhCgH3dP6YxQvC5DQfOoi+3TmN5/BBhsDfua8w9PALPUyYG7U5GiynWGutGIFaxQ9l
         fPJX9+m5X/dk0mJFVj1PB9Ck5AESxvzmURzweiS+2EDfuEiEcKUwQcTz5GSWXJy1Rea5
         lzLqIsoVMFffFa6aCxUBZ0gi0Qo/cvaEH0BcS1WBm2Et15tpOPXJIYRjG+OylV6ChsZC
         lHqx0SXh6o0CYq4enByXhybqzY5PASak0Rcg61o6ljO90URt6UpaOJKZWT0osGZavoWt
         UTHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=GP9LwF+HWi+ASeTPUXqiJQsQOrRCpxbdq63TxTzr9OQ=;
        b=DT0lpN0sR5gkiykPMBybC03dfWT96svIokBKe7mIFe+wErzc8Ft0d0DsSggIVh3AB6
         QCw6qhdWee50yL0rhVucfIRlUKbpiDuk34iIjXw/OpcNFxldZHVTw4AoCHsQq4IkXVPP
         Ih7AtjMTo4rtyYVjz5rF5RVJe4T3Ifgeq+YU2AcHeo0NwYhwiCWgTerAiDINe2wQ6Av9
         L6DjXDpdstw1MUcfbqJpwCf6ZotGObZPnd2bOqhluT3aDKPW0S93J44qObc55sWPM1JZ
         EftoLDzB1r41C9yDgyP00SfAfLRlDH4Eze5WidwNs/gEomoeshWB7CUJg9UgB3qFJP0C
         5PfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GZ4Rpj8L;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GP9LwF+HWi+ASeTPUXqiJQsQOrRCpxbdq63TxTzr9OQ=;
        b=AyrGdGBLbX09HhA0iP6yvWnamCkyJ8kBcJKT5nwLs/V8MCBb8M7RTgnv7Tz1DYij6e
         /eaCdpSibVBVRyZ9KVOp9IYWGu8WBSqmKBX43xQpvT9a7f5gIHxp++Sf8YHs3I8wwASt
         hU+pCB8D2bg+4q7cwMUYB7o0ckHRuQ1GbM6RXFxkYj7iFxEYHvZN9U8oVZwcAR+b0WGz
         xkWDAIgfmafpdUnjGV3yu03KfmGggh4ENBZRebmNIty7TwjUAPzdFtbb2hdJLKqPfrxt
         GvRwcEYImMSDvJXJwNYo27mS3kmXiTNbwGBePSRa7yiIynreb2imRPSEOfe2QfrmyUyF
         SJvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GP9LwF+HWi+ASeTPUXqiJQsQOrRCpxbdq63TxTzr9OQ=;
        b=lLOrrfJv+NbedfSZfpwT1g7jX3PCVpbyYb4ZeKjSJyfNZ8PhSv+PriIOlLrLwof3/I
         TRRBQUkRLquhUvaiwoCeGTuwnXZGBCtUekP7cgTgCxZseYt0oAWUk+1nOmozEgQ9/hs5
         o79AsksBejBmDJcixB4EmkoRZc/2NHMjek+lFENdBIEXyCLQrMoz6AaUpg6oSVOI09sW
         e480Z/UtfJFncIUOwUIMSa2KvrJ6NXzEy0RmT8+lqndbG9xNUnteXR+HfdC7FQt3BJ1O
         fu/fdSUuWhp+055SIF5BNUV/Js0sxsdNVhZKboikZu+JfoioR33cfTBSg531Pb7fH/Ra
         HLqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326zl7s1/nRa95FgpuWrSPKyrBArSghoMgQzv0gMk1eGhBW0ZcS
	Qcs6SEZhKk1oNkW1K84n+lA=
X-Google-Smtp-Source: ABdhPJyl9B9nXFGWMxeFsJbVVLrfBSbw8gZkel3r0KgN4cHLRNRQJ68V+ZaCab9KvT6Ga/kGXoX7OQ==
X-Received: by 2002:a4a:aa82:: with SMTP id d2mr8127326oon.52.1615308473778;
        Tue, 09 Mar 2021 08:47:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:10d0:: with SMTP id s16ls5466237ois.7.gmail; Tue,
 09 Mar 2021 08:47:53 -0800 (PST)
X-Received: by 2002:aca:efc4:: with SMTP id n187mr3466552oih.85.1615308473380;
        Tue, 09 Mar 2021 08:47:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615308473; cv=none;
        d=google.com; s=arc-20160816;
        b=BMNFCMEn5PJJhs+B7OOwQPKyi6sbYOM1eqSsK0c1ug7x2eyJ46TFEoy2f/2S/3fyZ0
         Yu6q6CPxG+L6GMWIxnR3HxJmH5mAvqdiBfSL7WvMjvNYHeqsLk7IbE6ksPpCp7vktLCR
         A5MZYCjsufxwkwpDbotwNx2nc2I3FQ7ZFuAPrwamvDy7gIN9k06tm6fUXmKbECnIsAqh
         2kGLQi5cOMupeBz9o3/E/X3kqsg/AVX6/jcXTOsj8jGrAd3DNtClSv9ucPVXO0cbpdGu
         qrgekAeuyVodGeI1iThtcf+jsKHI4Y50hkECS57OimwtSoRpmXs4p3eU0IRGsrAWZBFE
         pOuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=t85zWezv3+ON+oh7zjU5r4y4sTCe7zdYaJnZowiC/Ew=;
        b=D1boaVWbhOvTSFtQjb7061pwm3HOSk+CbFNkjoDKkts3//veOBZqYBnKEUh/KDkETy
         n4ax7hlhQMPNPAOXH021FZ5kGiHgpZ/7dAa3Uwcd4Y4qiljvOtLgV64tqXKFRtU9Cc5Q
         7kTsp9lVmatZYPjSuyGJbnomqxjGVz+LV4qiD9rF45fqkuDFy9sYuQldndMSepopTWcq
         hNTyAs7qSry4URV+4k0XhAIPXKLYJllzdl/WYbKNhzv6V/BN03iHFaL7fBD1JQQ51bRM
         DjO+KkeIjrFKdWC9dn5PegI4nMwr5jyqgbW7d9wopF5czT/7QtCjhnCht0pbjrxbUlXY
         8D4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GZ4Rpj8L;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h5si47863otk.1.2021.03.09.08.47.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:47:53 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 5310465237
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:47:52 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 4F59965368; Tue,  9 Mar 2021 16:47:52 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212207] KASAN: precise redzone checks in tests
Date: Tue, 09 Mar 2021 16:47:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212207-199747-gWC26C8q8u@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212207-199747@https.bugzilla.kernel.org/>
References: <bug-212207-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GZ4Rpj8L;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212207

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
The same can be done with stack/global tests and perhaps some of the others.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212207-199747-gWC26C8q8u%40https.bugzilla.kernel.org/.
