Return-Path: <kasan-dev+bncBC24VNFHTMIBB2EVRT4QKGQEUWI6ISA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 19F6B233810
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 20:01:14 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id h8sf7446760oth.20
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 11:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596132073; cv=pass;
        d=google.com; s=arc-20160816;
        b=BYb9/fQLtWdV/vByPEObpXZgA+UkDehjNW3rNNiVCevD/VY/qkgdIyc2B33KGyIxAu
         U30MwXqknG23bvIk/KPEZ2Pa3FwFwlPrNcjnifdmlAkFl//86W0BOYppilhGDnZ3fkSa
         +CrtYoF2QsA94flYnljoQxDmszVM+iVQLSwiYAEIgp9Na5afqXMtFBXopyjEMcTX6goW
         qJd6gQuWL6xXlrv//kDPEx+3ZcyzqiPX+ZlwYDBtZjBd9xchc9tmz/mXiYWXQG+YN/yJ
         c8eW7c4z6xwjIMGFHWoX5ciSVOZi4MvjlNY950c4WshhTF1Lt1DwybY+j8NxgRBsUD0z
         pcQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=rxT8dqXHb/JVQZN3n2WNbrhkU7FSlNct8x3VPHdONng=;
        b=Kb/5BAAJP2V9jKzMIalr4RD4XdBqYZ0vuTl88WTigatRybTLQVCFQD/9bgV7/c9/DV
         RDKZq+fG+oeAqxj8pF2zCmA0k6o6xZeZyuEEqShZBAQCzj0zWLO9deqeH507SsqTvc5q
         KYW4yUij/O8ZpEjMqozBMkP46Dc5mMLAEiHfW8xu39FAVUqyhWZvMbMcJglte/Ib8VCy
         NiyS0i0h0h/OHMgkLocqHlBNuaOI0DM2So3YXztd3IzwpNMy4zka19o6ZOYACEG7xmb7
         G6NpiA+hcLXC3BtDnLVJJgDBuU3OXfOY+nkMLEkKrynYgsMnZYTlfAhJ93AGDT9yh0OZ
         cKgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rxT8dqXHb/JVQZN3n2WNbrhkU7FSlNct8x3VPHdONng=;
        b=Ie0gttyvU9UXzFn6QXRzZX/D1RAuTzAFsgRUa9H7qwPGEPSYbcLbxSJgpyFC/d6vLd
         wzvuScfhvW0EmigRbnQM+HPiNvdvUzEyUYSrsNBfZeFkaw+cV6rV0gQFXwGPhK4IVmXE
         M9A0ddmuJfD/m9/3rqsguDCMHH6tv/OKXUxpj7CxfSjw4YdEoZUJKMJbvprxWHMpjpUc
         JjZZzphfBoeYr8BQHy/El3jUJA8obxP4vqbt+t7ZOb/FOtDZyhN0dA9IgVsWzaZwPSlI
         VdpzLckb0UISkAxHJquf+vphsUsCz5DUu36tXXPyauUIDtYYH/bkJ0IJXfY9J1h3pZCM
         mZsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rxT8dqXHb/JVQZN3n2WNbrhkU7FSlNct8x3VPHdONng=;
        b=T5c5qaHa5vsWiQAXF50OnCYhVH9fZv61AzfTjYWwEEdZ/1piGYHD5Nw1jhnpP63yN/
         aJDhGuXPIWY/g3lDTau7GgG3jYtbsNh1N7JRBYk+Td4P1MMFOXXZH+O3GLxiVYaVvlTF
         R46H+LXBjRwmsd7GIKb1GKt+aHxNuy5tltg2B3aQXTlQqYzi7dXtNGuXt28K6Ek8iuX+
         U1JqHcc32EBntz7pUniz60Fq+y09aCY8nS60a2jVmunzjhi61dv9L81lyHyP5H64BG+G
         OPgjBWy9u7FDKN3+H62bCzvYJo8JyLbZN9R/9Eyg6ubmv8GtG1IaqztySWqGANIbqic0
         4G4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lT2GQEth6pFaUUEUVBHB9RSDPGf8T99ShvwP00PbA6wBtZAm4
	Kaw0LsFXmS4aYtYbRIsVt4w=
X-Google-Smtp-Source: ABdhPJybGBfv3Q+MOAjeZnR3r5BWiOLogPqbzpRUe6fba8VM1kQh0QN03X65lRgcWM5Ayuur0Kn6hQ==
X-Received: by 2002:a9d:454d:: with SMTP id p13mr3197003oti.126.1596132072757;
        Thu, 30 Jul 2020 11:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ea21:: with SMTP id y1ls379987ood.10.gmail; Thu, 30 Jul
 2020 11:01:12 -0700 (PDT)
X-Received: by 2002:a4a:9789:: with SMTP id w9mr9663ooi.24.1596132072441;
        Thu, 30 Jul 2020 11:01:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596132072; cv=none;
        d=google.com; s=arc-20160816;
        b=QES4nwAxGx2E28B21h6isjJVqtUKRDPe24qawU32s2EzNkCTPCgxVO4K0jPWL3TqH6
         HYgnbbX0vDHQ7adNoVu88q3Z8VjZeaN6oWsFUxHWw1GD/CuG/vJTB6v29vXqVesp+bps
         m7hFSOXYyuxKgVctkCtwL0Esu8bCMqzXXokpcfAXydiK9q75tKNNdi/8fHjURVzNVZd3
         vOLP277remv6shGbeuGU8m7wyGLQrLGb2W5kS0WSqaEeoqtbrlX0Vbir6VuJq0qOj04Y
         WnznzvmeB4ZsY+nWLTAZiBsdnqTXxQjahehE6IOkFMuj4wuYUrazlayhvUQdPB39PxXx
         9I8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=FYdMk/20w3yNRn5KKAgRRcGi5/3P9b741h/DoylYULw=;
        b=VBgXsfU3cSmgzKGnr68rnbMxHWW4SLhWdE3Ac0qWoRJRgdPksTNBspLsWDQWZZjRgx
         nGUwDSNYfAybLiMLy1teJtR87at4+GO8UlBZ2WkzSmxPsw0tB0SGZ6Wkbu9+U8BLYw0b
         ljBg/0qT3BrqXLHJ4S0ihLZ00VgL3WvLJpyAiRU3Q62y8e8DO4DbfCYMP14eN1amAib2
         9ixni5M3E+ZR6jCTwaVe03OFl56tm4sIi/4rnWfG60Ctfd8i6iPOsiI+yL1qXf7GpC3/
         XD4KIvQTQK6YdfVKGVJahb0t+yxjpeuB4Y4Ei4/HhHDlfJo/bG18EPYZMMW9++VTG+ji
         bLSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n22si483117otf.2.2020.07.30.11.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jul 2020 11:01:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Thu, 30 Jul 2020 18:01:10 +0000
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
Message-ID: <bug-203497-199747-8ru5seIXLc@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #20 from Andrey Konovalov (andreyknvl@gmail.com) ---
OK, finally got to working on this. It looks like the issue is caused by HWASAN
short granules [1], which the kernel doesn't account for. Let me look more
closely into this.

[1] https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-8ru5seIXLc%40https.bugzilla.kernel.org/.
