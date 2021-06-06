Return-Path: <kasan-dev+bncBC24VNFHTMIBBQNX6KCQMGQEWY53FVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 19B7E39CE7A
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jun 2021 11:56:19 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id n3-20020a378b030000b02903a624ca95adsf10389531qkd.17
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jun 2021 02:56:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622973378; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGeb7ff5RyaXuYl9SR+kto/3h0Icm4LCLq/m4NeoX8Ny4wGALiEpzJjviIIp+OwRpt
         wbkbw7QzwjehT5uCJ4drgf6XolKbw/uZfiwKms+b9E97f0ckWVUQAZJzIY+MdY7UuXUe
         6JGIk61mT3G9Zs8caxJt6Vkkm7+mmtiGanHnH/ppCW5e2BdcitYb/gJe41rRmPkbmw8O
         p8V00hpcm6LX/GssqgB6HFPZpflqtDf/HrRzM9WPNg0jo0kVMpZUtN1ndSKqf6yta0GO
         AdLLJz1ieWC6jvTYDVoLidcvzJFYwauVAzaakNuY8BRwSf3K6tx3N8noocPbYjRVI6r+
         3suQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+3+aVKZQNLRKm4hyR69lSvOToERpMhNmrT73I6y96xY=;
        b=bCIdJUG6k3cwzwysJ27uDvqt2u1G+4mtbgpz2hQbeuNXBafhwpOwlGJbvsDeE4vBKn
         q1Q6OIUSX0j3AdXqBIPza3Ff5r1ZgnnEWN1F54ikkVwnaE58/dxroI1ShwYKfz42b4tS
         1VN0LHzZdDM8Sl0ylvyte/JVf3D3qIhI6XoXET37th4Fnqvk4hFL0NufJmAsdfSWjsay
         LzeOMxRnl8uTKcCqMfZHurIyARF+j4uczzC1hiDkHfX6AQNio5szZcfNL0jyu7qyd1YC
         kbneC5AQQ3l9F1ouGNUw8d5Q4+29ZnsJH2ggD1rMyMDbDj5lE0TntLRVU5DrHB1K8vx1
         fPmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cq0pLV/P";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+3+aVKZQNLRKm4hyR69lSvOToERpMhNmrT73I6y96xY=;
        b=oNkkBvujoDI7BfJK9pssYZUKAeegdWGR64PRlPrSWG14NME+hDWVK+hinlLLCO+alJ
         Sy7eRdgxwuGNFny59Av5Ti++R244u4sz3eUYSXGV4ObhOBsajTyLFquxHsy5V3pdJl2u
         qu2C16Ek9i5nN+6lquAGXGDYIHg5cUSsoDz1CtKX7HxsyRC9MfUrSRwVHRMvFdxwj5ut
         dJnSlL2JgRUZGLCpkkhRQHE8gOlz74E1Hyoy1XU3XAERtsYkngLE+WDQ6KsvZsWLMOHU
         VmzR68KvBsLwJGwljUkLJ1UwTZUyRWu/6o1xoEX/D2jvwfdty3t/oH4LxnTO5tbQYCF6
         dZDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+3+aVKZQNLRKm4hyR69lSvOToERpMhNmrT73I6y96xY=;
        b=jng4eDnyWncAU+q8YcQHvi6lpK6gcgkpNUi+gAUFuXgPnXztEtMrLyVRj3UnKX6tAC
         2SLV8fLDVFhl7P84apAOjcsAKWEQs6ct6ms6sOhez5oIdv6JyG2oKmNoj6l9rM98NYYw
         jSckLD/t8GWaw4tqrM0MYUBnh6ftKqNYItm3LuIrOSncCuxtlN4F9S5iTe7kGwlUdIzS
         kBE9szyfA8qVraBpnXv4dfXiXl+wJiaRIGTfgbyxq0q2GbPNVZx+xbLuI7rGhiKc+GUE
         PfqMgY5L64yOfQMzV6wnTggkWBkrAUxxFqdxLIuFem+F+BeK+PtJ3bHQPjfP1npsRZE/
         gVIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pG7vTBBdL3VNDDLTIksNNEvT8/52LmCCPPb+bC6ejAE5Z9eEe
	tBwxt0GjDYo0b2LmyZ6FA+Q=
X-Google-Smtp-Source: ABdhPJzV9vZGgWbR37svwcit+FnQEZr/9EFYN5QzpYrGjkVa+ae02M2fgXvP04zuGjMK3Q2FC/Zprw==
X-Received: by 2002:a05:6214:2a4d:: with SMTP id jf13mr12580153qvb.41.1622973377883;
        Sun, 06 Jun 2021 02:56:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:50d:: with SMTP id u13ls5135511qtg.3.gmail; Sun, 06 Jun
 2021 02:56:17 -0700 (PDT)
X-Received: by 2002:a05:622a:2c9:: with SMTP id a9mr12128147qtx.38.1622973377468;
        Sun, 06 Jun 2021 02:56:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622973377; cv=none;
        d=google.com; s=arc-20160816;
        b=qI676SHT3rNkdRdk6s9h4qz5Zs055ACiYRSAoSi/VM4YcJ5S/jg7y2PHPlOClVOAuY
         OsgFzc2R1Brc+tWgl6WSuy8LbtMhkqcxn1t/OBs92Ab/LDvbvq3k5Q2tssEBnQqjjocH
         pKBJEQVTeMRnT54Ma4HGuAD8CtSOxHB08Sd74ydxgD/A3axCROvTZH8Xqi/ADqZ9OHUq
         Yd+AyFahaod5BMGj4l2bftZVzzKk1KDet0A8+toC9ncQJYbOqpQJOwhy9JCWRAlmvZmw
         9GEkGrJ1hDtH76nX++SMBsscH3DAUocx1IyT/QFZTYlJixH9uD0DPRsTlgPBZ5uGTTv1
         f+fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pajRhOSd16CI0m/EyrmVyO/OMGXRs7RihC0+QQkkEUI=;
        b=JRzqislPooKjx/zCEkdkS8riNspe0MxpfXCPGBN0bW1YE4XH9cqyhNqqCo8oemqojY
         FgLdq5VCP06tRpZtRD+OpNFHwFBI1koWGDh87O5b8Y9EEHogVg7hWRnNPVBShcCrAwmF
         ceehlIzgNtm0mCAmQHdFJfen5DFjslX5WFhGtxKbD4CbFhS06Msyi1bsb5T/4Ac0Xh+m
         hM1GMeW1YGaJHJiBCrgxUJwDQM6bO/nrx1kjDYjEsYCBYGwYYV10xi9G7hmKpyK5+oDt
         nnq5nFFSsHU2ZMXjOAUekv6OPHiADx4j+h6ha58qeVBAM+EDKK/Ba7rPuslDHZnv96iF
         jXNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cq0pLV/P";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m9si335189qtn.5.2021.06.06.02.56.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Jun 2021 02:56:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 5E490611C2
	for <kasan-dev@googlegroups.com>; Sun,  6 Jun 2021 09:56:16 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5226A612A2; Sun,  6 Jun 2021 09:56:16 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Sun, 06 Jun 2021 09:56:16 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-213335-199747-KrQkhYd73d@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cq0pLV/P";       spf=pass
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

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
I bisected this to 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings").
Haven't yet looked into what the issue is.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-KrQkhYd73d%40https.bugzilla.kernel.org/.
