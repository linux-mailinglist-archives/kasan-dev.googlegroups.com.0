Return-Path: <kasan-dev+bncBC24VNFHTMIBBWOGRL2QKGQEYZUQIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E1D181B6FBF
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 10:29:14 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id v2sf9006138qvy.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 01:29:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587716954; cv=pass;
        d=google.com; s=arc-20160816;
        b=tK7/dzMWUfyDBP7BctFI6SBZ0QpuFGEY65HW3B0rFNdigS7/9dK9SkiLZAubkmd0IP
         KuN6xdAmsJw7R+wicuAJBroR4eMOlD0KKRE4qXju8EP6GnmxnULxIM5uFHIc9KVyxlyO
         GY7PuZEahkE9Y9xKuCM2GO/EsoxfcAcaxgy82Xcj8I3kEVrqsxWhVLVuYnvw4IsA0Qxl
         QB1pqF1e3GiP+so6PTjbBD1cj8qwJL04lRTpMWoKSPQh+iq3y9fRxRxQQl61w5euZ+yC
         MXjqvAJFVyGrceilGqtWr9Ub3FTTrmRvYbho3y7ooSp0t86POMCa/L27FBntqVyb8Vvr
         Xlmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=QZ/PP0lxRAxxgXGTVXbCPjbitp0fhMpjSjeRPxok6Y0=;
        b=E21tIh4ptmGXK4WXqkVqhLWsZJ+Xr5s9yTTm0QoufYhQtWBdvlEJqnv6d/ZFjbRXWV
         NwAsQEU5zSUAJ5TTUS4th6TXYoUZFjo9eyuCZMlF8eggJbL0dzBcn0k375styIYys+EI
         oCA7EOKYHLrbjfiYYW4AzR0n4vye0gLWYnbWPVlKXR4UIaXIwqYGvxoN7fLjo4EKRzCS
         wHVRAeCoHsUIsQ7X0Bo7ft0tMRfasEmgJFlijfBbBABhRUpL9U8kQThY0MfHqcY8K/c+
         RH3/sxwsmk6gyDcWRQKp/OBpg38XV2VgMK0UivyeAXIa13Vb+3mChpzUda3kaRwd08i2
         5ZUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QZ/PP0lxRAxxgXGTVXbCPjbitp0fhMpjSjeRPxok6Y0=;
        b=FC/Tk8d4qzqbLlAoswe2IzgGWpzcvR233wvtzDIkONHtB7zLnSlQj01EdQABBsx+80
         SOOx5lDOENBstkDnl2kUMcPb1I5LdZXGVuGKgX5XbNSSRUEcfy+g7/RJG4EYhpDgd5EJ
         RyM9tnE3HJky+B8cRV01Ssiw42LxlxiJl3hFvM9fYJLh1S1Gm0z+Uewe3M/VgtPV+OxV
         8qGG/0xBA1sVH+PoO4Iy2LAFZlU4nvuYdG3pGQ2JcCSl15G0tcDMtgukgXVnBzVpmPqC
         MmqCI2Z44DlykMi5hdr8p8dq7Pkql92fXaOijqPd5o6vQJITHlL1FCW2pGmw55ztmSn9
         oBUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QZ/PP0lxRAxxgXGTVXbCPjbitp0fhMpjSjeRPxok6Y0=;
        b=YbPo/brVnA8oVFTeLae1WfebNt+K06u0fbkJqu4ios95AstzwOgDG/RPmtI01eo6Hz
         c8U2veWt8QlnI51zC3qoPxsjQaWbS/f0f6ZOR99PsKUca0NewPSqtjrdcD1Tqi+pEdGT
         mv0K9CBFNTcg3yngy0ORQovY5niv5RJG97baSBz8T8Q4HX5EcTJx/YBhm84STh1KoJsQ
         rqdXAGzPurAeyZhLGCXElHVYoTkTytnXIA52IbNqsSei3ONRemvNBmUuewreXWSWfRMx
         OSQxcX7OlGB2TlybY0if5WTk8BUL0Gb1+Z3pqcS7rNzzs2ENOLztQkXjzmsQ6rVpsoQC
         +9gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYRQxC7kdoWKhBonsooQm7FxSgzBoC1XFniz9TsfC3qbgJOy2nL
	B2g46nHTeUpMvzhdOGoqFc4=
X-Google-Smtp-Source: APiQypIbaAW+104tUiMuS7rrGRhpzMxItoRNKIAjGryUiDZpxkWW59Vp2+arxRI41PfW6O7NuWiKYQ==
X-Received: by 2002:a0c:8d48:: with SMTP id s8mr476910qvb.114.1587716953987;
        Fri, 24 Apr 2020 01:29:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9d8b:: with SMTP id g133ls2589607qke.11.gmail; Fri, 24
 Apr 2020 01:29:13 -0700 (PDT)
X-Received: by 2002:a37:6cc7:: with SMTP id h190mr7757025qkc.115.1587716953686;
        Fri, 24 Apr 2020 01:29:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587716953; cv=none;
        d=google.com; s=arc-20160816;
        b=noBTD7y0DxakAYoiOZOyC77qpeSgaqRVb8y7QikIyxnyevhjNLWVrFho86+Y2prtDL
         wbnqc2IYp86b7vpvx4cvxmi2S54CyknvzcHTorxtpj4WVUmeDRQc3ribyokrSFGND0a7
         caUmUpJyKhJ6zmL+/eFxgANl11CJIsOwalu+8zcIRfUMB/b2+QdE7XZjDADUpbSS4TNt
         swRoj004JBiH85j3uOrHrDvEAThewmeKKSYe0cgWz8Am21kVnXDVKry0deYPnrasaEsc
         Uod76Su0kyAdGX9Ex2yj4tCk7jABO7pwB7Oe4kZp3+W+wC4wprRiklsG89m1NvgDgHFX
         /7yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=dcENjY5zlZgVIPE8X7WBoJD2P9LWOl2yFqd3UY5SCvg=;
        b=Qk6CpLMuGUBhNYefLqcHLGSOV504It1F4cFKE1frsb1rwcUfhgvq9S1NekcZmTkpGi
         uzV6/1LJIohVdpadb3y2fmYksnGbSms4Gd2w3ZKA8CPcsy6ZVw5GIyubIlhn+dggOKsU
         jqCqHDgTL+2MzBQzoLwSPNIt0Z5tOuuLm5Mt2fdf2f2cpChbmWP3Lr16VP+oVtuKoAiN
         GS1DOM4tXCzJogpPXXJ+IkQx/FL3RlV6FabjmAKRd/gauz4KexPzXkL0IkC8oUvGO/c/
         IXkJcvLkx/Aq+86cfqUR0IVxpCSlpzAl+pMmqlfpM096zYsB5Mvn+QWqQrXhK2Fkt3Sy
         xSTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j11si412843qkl.6.2020.04.24.01.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 01:29:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 08:29:12 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-KD8Kgd5vBk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
We should still remember and print the free stack. We don't know if the bug is
anyhow related to rcu/times/workqueue/etc, so it should be only an additional
info, not replace anything we memorize/print now.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-KD8Kgd5vBk%40https.bugzilla.kernel.org/.
