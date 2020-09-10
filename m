Return-Path: <kasan-dev+bncBC24VNFHTMIBB4NO5D5AKGQEEVGTQ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 84C842645B5
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 14:09:22 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id s19sf3451039pjr.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 05:09:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599739761; cv=pass;
        d=google.com; s=arc-20160816;
        b=UdNa/LMHDikW7q5ap7AMDI+9T5w5lnsDS/iXFA1bFveBv3Hi6n3SDbOp1f4vjuulKK
         afv1ahZHvif/2+Bvl0K2rc52/wudQm0f1vgCWWwPeCqI1LeSXyYlztVM2r1LIHb/ZHUi
         rieiK5PdTR3veYwLO9bTe7u8unzo6vSxmWQdx7IBtqVj+T6VS9UNG2tiTr1i09bwvGdw
         pzOlLYdat9U1Dyv1E+ZWtq9hGu4V1aghsLEgvUQVdLUkBPAJdcK4QbXPXc3zw322XZe/
         cTvUfpwcEHKxRaIx1/7oLoRTonlZKE9M64Tq1dsZBY4aYU4gJXL/SMJEjQFqc3PpskdJ
         Fd9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ep23ft7WmvjmH0uSt87gM/jBfS9YHrTauirZDglZwwg=;
        b=rubinBv1kkKMWhDLo++36LR7iQN2/cxnTQqAp/iyqbHhaMkDEWIogFNSXQ1ve3qAQ+
         M4cs5hj2/wtMxdvcOpHX68R9CxJjPxZGq0Iemjlzov2aC90pFfHAaDnvXpiOvvYpDPSO
         DSo6n7/HtnbbsbSBVM3v+J72JjRI8DhnD3FOtjjq1MBnyATCT0SfMLvno/fxhz7aPS3X
         kmQrdMrzZ5RpwZ9NH3mc58g8ITTllTGzT0OfkUZwEtZfiMUZUGU/7jW+29vv13DFdy68
         plmX3k56N0hF0iXT6b8nSXfZjWwoEf1W9S60ZVtoTPrqEyHgexW7upcso+hRtBdZ3oMA
         tmjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ep23ft7WmvjmH0uSt87gM/jBfS9YHrTauirZDglZwwg=;
        b=YcWfDj/Dzvj896RS2tQ1MwJjAOpc5B/2dbb0vzob9lYkjgrrsYeRFgmq53xdeNsbED
         4jsJi0OGeDWhIgaLpyFJ3OcFqGeVTASI7JDGsxBlYs/+Jiu3ynlu7ZenqD43kkL/0/EC
         imxfG2Idu+zyeYh+69SdTS0m+zkzsjUrYhO7qwvD5J9TkPcBrubNNOhiofIyQ6ToKGep
         nBg8qQT8dEv4Rt2aPQ9B8fKZNhhEQcgHip+rjlnT+iaot3/oXB0TOzRivE9F2Xo5rplX
         NJ8EuAKcVyiQ1z8lPFts2G0CAOqxLBiiZsvC6AS9bi3njpExVgv6AWJNEh1V9tgzsnvb
         7mGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ep23ft7WmvjmH0uSt87gM/jBfS9YHrTauirZDglZwwg=;
        b=fejUzx9KRrE1izh1O+cLnbvurRYZ6SqOYisuL22QC23/7B9Ri97hE7pdhRFoletmzL
         n3WkdEpy3YEqX5MfubkDVN5PsEZ6KcTdrigIZWA1QYdwb5ItR8wQsBtyZjIpUQ2C02uR
         hdQOVEkY8fvEy7XC0Nsu68y4DFl/USeuTb2HkXAysK5zVqbrOXe+Lxu2oxgNnK/wg2JQ
         EsGOgKkO291iaOzeZ0Vz+eDZOJZGQc6Fx6EKRavRhNVcrzQ9gRL6KwghDtpgcf9LS5aM
         Oz6ksUw24KQK5bdaJzgSqxbsU8uvyuB15jzApphKrHilUe2oV8jaswsU8YJxB65ZMdVa
         CGNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FTu9VD/h8z1W7NYZ7l8KgAKQHahju1xfQXadVtf4Rw3TR5Y5X
	bd0wR7+vyZ8WpIlsogEsTz0=
X-Google-Smtp-Source: ABdhPJxnK5UYbHEdb9IMLuhzHTwnpXddNR/mB8CNWPUj520BGpRsvxfrMUUg2VUEuiHJILK1dn7/bg==
X-Received: by 2002:a17:902:ab96:b029:d1:920c:c22b with SMTP id f22-20020a170902ab96b02900d1920cc22bmr2212739plr.28.1599739761196;
        Thu, 10 Sep 2020 05:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5a45:: with SMTP id o66ls331784pfb.7.gmail; Thu, 10 Sep
 2020 05:09:20 -0700 (PDT)
X-Received: by 2002:aa7:9991:0:b029:13c:1611:6530 with SMTP id k17-20020aa799910000b029013c16116530mr5012866pfh.16.1599739760567;
        Thu, 10 Sep 2020 05:09:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599739760; cv=none;
        d=google.com; s=arc-20160816;
        b=nd3LrpW/jkh3uuXqPWNG2tcVxmBC5QiaRxuECN+QV69avxvA6Eo2LfyL63P1Io8FE0
         XV/Sh6YzkOprM3VuhU/qiCBqYNnCi7qoFoIllsHy9g7MdSY8Cj6BFR3y4hxGK2uUtkzm
         aDfBR44R9ySm1R45/YcBd2+I4cQGVCqo/NweeU4OkcxWM9Cu1GdgHInvzBd8nGHN7vUn
         SsKIwD7P1weQn92Yle7hJgjpbmgIXsl6QfAlv1dCeLtPFxY5dWbq8R3RXb+3koBVf6qo
         wiL4K4IwUZaRRq8v9xtVbQ+FG0jY0Iuc569IdnW7FDBcZ14PrRW7Z5aL6i2MpJJ1Qrcs
         BW3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=OS6CKAQoh/wMhkt9xWafx0GZ6h3ANxsK1QjicYfUxLA=;
        b=bteODuZZ8hXYaJZ2wT+M5qyC1r6+IudbniHT2Bm96kmZu8YFMqFKZBCsrlh3lD96wh
         iFXo/teH0i3lFQVX8yIyHU30oC7qA7mKmrXPTpOJpl3rxQcw8P3pfBstlgfp+ALiM5zp
         8HRWu9A5xIcCyT3mxoKsnyzPTSc4YFW1Hgi9PWseOzsJ4wzkKG1JUPWCSb8dHBzhGPB5
         l/X9QL28WHLpzP+8dRG7hPzhHBB4sjycA8uNe0HkdB8QHP5Z57AQAbzli19eLPmZPpl9
         sb9IYJDRWtTzSw1aOJXzNTnD0I/aL6g+ah6KzJaH4UvI8K0QucExh9CPraoKbDOxxDsk
         5YtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id iq17si91348pjb.3.2020.09.10.05.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 05:09:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 12:09:19 +0000
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
Message-ID: <bug-209219-199747-Ryu8A8M1LM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
I think we one type of systematic testing is feasible as well. Namely,
one-factor enumeration like we do for fault injection: delay first point in a
syscall, then second, then 3rd and so on until we enumerate all of them. This
will require some debugfs interface to arm this per-task and query if the delay
was injected or not.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-Ryu8A8M1LM%40https.bugzilla.kernel.org/.
