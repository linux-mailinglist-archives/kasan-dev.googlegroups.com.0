Return-Path: <kasan-dev+bncBAABBG644WKQMGQE7C3R25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3362955B8B3
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 10:45:16 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v184-20020a1cacc1000000b0039c7efa3e95sf3280585wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 01:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656319516; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZvBxgzZpIgNudQPNDuOlnZIOshqrbOPfwKKztlpN9v2UEYy42NmxgBkFF8VoAmMETK
         7UInA6MibsfIkdmPae7iDT3S48cZueODQ2Pw5lYWd0TdM+uIftqWYuuooACLlIP3qsQd
         C5pd1kfz5eJG64iCv/dm/xhSG5MXBRajW781NJpa4SJpgmYQ9q+GDeOCP9NHoJhxZYnO
         YBNQY3xK0RS2EoVtnJ4gJkZ8P3SpzcWL4RGEVCQGbSirteg//1laHXdrhQs9jel+KAJH
         WryrKbb+GQZvc40eLwuYIiWCFTG1getmAzJNSrodAoqO+jOgr/0KJyOjMuhJ0/lm2G7h
         T6Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=QqHqH5US75fQ5aNcGwvCiX+A1GBZw4OJ6hcZGj1ARWE=;
        b=Evf9EK4ju7uY30Uzc/I7bl6pOv146TNXDGP6ubwea5jdcxI86p3E/5JorfK06GvTvF
         61rB3EKawEJuDUkYwWAEVmlHi/0FD1zFtMhJx2ayM0+qigbRjkwR4VnDSLCtIbIZHcG/
         q/6XQVcEOd5QXBn1SlCMPB8UpX4lCY6DZ7zeqPNvZdnFdTcsLmWiJLp+G/Jw8ji9BPfW
         nWsU6tLpw6KzagfIrVTMbQn87WMFPfZzJU7TrSofRfRvc9DDv1A7Q5FpiqTGzP1Sj5tb
         Qce7IzHiHF0dXYLEmoQB8jfFCaFJd/5fOJSWz8lBOx+VIw90shmc6lkLjbR+HoyhW8xC
         L5sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="iW6f/m4n";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QqHqH5US75fQ5aNcGwvCiX+A1GBZw4OJ6hcZGj1ARWE=;
        b=gFbPxt4KOYsuwRyNFAYHMfHy6boFhv9Jpbn3wdaDpyfLml5dckTEFP4vFDtP0Vk5cQ
         9twnCGYpziR+8dynmrqdNNBt64BMA2ngKt+R5KnwEg7oU1Kum2sUyWVxb0RXL9/V4D+L
         MRywVg/EIUlBIskYLjRTA4zEH+LF04s1slmMFStx2PS3V0R5n9kEdW6sYHetHrdbzZYe
         AVIVZ8WpWKQoKs0eKE4y7IKQj18PDORA6SRVqctSxkYzzYSzG8WrGpFLjYWr1GKUfNu8
         Uo4Q+cV2qIRcpZ7jZbLYyElm+pade75PQDmX+faqduLt3orn/sgVWD1k3TNDLv22nr0U
         362w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QqHqH5US75fQ5aNcGwvCiX+A1GBZw4OJ6hcZGj1ARWE=;
        b=MMMgHE3szkbriyM5Ipcl/Gpru9yMz4TqzOxfzwGZq+kl8QlhjomQdQfLVdCMuotKZF
         FXbDW9Kx1hdNJA0wFmYUMb20p7Ecf3erkv7VNREUSZKOFfB2KkyDRkVnmw3TFcQUVVKi
         689rtsoPohcYf80C9/tyYnvEnlG39x9gzmyqe7Ci/rhryaueTjhIJJ1qpE0qg+LFF8CG
         /++MiUWCnNCwtvavQ9CLF0CHV4T1yWlqKnPtquJ1KAPMJKfisxZmTj9es8CpzRBv/b6O
         bNNbYYnFrlSKEqV0+W5cfL0ctZXp3PMIr3ia1yCg9/o8Fb0sy7UdaEjgsQAN1OhQdR8E
         flNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+H/yYJ1NFzjK8A3UiTwP6MHNvQdNbsbJaZ9a7W6Nzx+sRqJZZj
	ghr9wchJ4jsw/jnDhnni5kA=
X-Google-Smtp-Source: AGRyM1v63hRI9kTaklYzWtpYgjf3Ry5jM9hMi/i56acnHdVczoI/50t6oW1AiHJiZ9sLUDFKLWIaYQ==
X-Received: by 2002:a05:600c:2298:b0:3a0:31a9:710b with SMTP id 24-20020a05600c229800b003a031a9710bmr13890707wmf.115.1656319515773;
        Mon, 27 Jun 2022 01:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls4580296wri.0.gmail; Mon, 27 Jun 2022
 01:45:15 -0700 (PDT)
X-Received: by 2002:a05:6000:15c1:b0:21b:ad5e:2798 with SMTP id y1-20020a05600015c100b0021bad5e2798mr11079100wry.237.1656319515069;
        Mon, 27 Jun 2022 01:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656319515; cv=none;
        d=google.com; s=arc-20160816;
        b=nZ3F5XVYVSFPN5nFfhyhLq9kBKFXg+KU0t2S4laCvmSz7+Hx02TAQ6L9SN/ohp6Z5l
         sjdKZKNtfQn78vBpY2ZFJa6cI2otaAktjEM6iN/kifZ2IphEuhWm2f4Segie82zx2B6L
         lOk0+HR3TBNDC7iuO9n96S1Fwv9WelzooEDd/24yExl+oIyI1eBOsDOsc6PRQCb5xvkL
         0+7aeEXp7jyclNa46/Va17oh2k+hDqexR1qJ1tXnNBcIQf/nCngzantiErE683Wodtn4
         Q/QQaFNEmsEeEkWHwabmm1PC3DgbBb8RheFa2PEp2jagZMOVQFLfnE7WB9o1ydCGljzJ
         XceA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=dECNcN4k/tx17azrUrsMeV3VR2Pu07J08dzCl8hozvg=;
        b=C6MngdOGdDmWG2KtnGX0FfHq6I03YsK/T9skL3hFZgx90o9KsGqiLeYbDIWwdWKb6l
         MbeQGrgsOlRTiAIno8Pb5yO+xqICsth8XHQt4LaT+RG51TJjL/W9e1doW6D8gVyNR9nn
         YKTU2wcfm87mSOzmZIV2zhP2FcoFm82yL9Efd9KO0K7xNbInJKgm+78n75PNmkCCzKwi
         xJQQ2ZTI77ixDzlG9pabJ7QY//K2+4LeoekM0jcJ21OgNdGXrF4COf/OZScJHxokydPO
         mT6yLIw1/OaTFFCCiU57cm3dXHU0i47dmOrixFzKw4m0DT01m0xCL3pUSNxt731WpdLw
         o8zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="iW6f/m4n";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c15-20020a5d4f0f000000b0021b947060b9si427290wru.6.2022.06.27.01.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 01:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A5D42B8103C
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 08:45:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 57E34C341CE
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 08:45:14 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 416EAC05FD5; Mon, 27 Jun 2022 08:45:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216180] KASAN: some memset's are not intercepted
Date: Mon, 27 Jun 2022 08:45:14 +0000
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
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216180-199747-ZlCtcid2pu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216180-199747@https.bugzilla.kernel.org/>
References: <bug-216180-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="iW6f/m4n";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216180

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
This address belongs to physical memory:

   ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping
of all physical memory (page_offset_base)

I think addressability check can go wrong for pages that were somehow
unmapped/protected but allocated from page_alloc perspective.


Does KASAN interceptor tail-call memset_erms in this build?
If the interceptor would be in the stack trace, it would be clear that it was
called and no point in filing such reports.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216180-199747-ZlCtcid2pu%40https.bugzilla.kernel.org/.
