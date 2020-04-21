Return-Path: <kasan-dev+bncBC24VNFHTMIBB5MX7T2AKGQEOSIR65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 016AC1B2AA7
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 17:06:31 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id k13sf14415104qkg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 08:06:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587481590; cv=pass;
        d=google.com; s=arc-20160816;
        b=H1BoqZd82axC7J/ZMVRxyUF7hchntVWiyWLjAP8npjo6NnCS9yp85TfvKilnxtGZuy
         FTm6AFSEdyYuYefWM1LuMSLS0bKv4fQfvtKLwyqKg5XAg4oJRiYl+nS7bu1Zmm49IsYj
         MHMaiVKJz8djjYb9vzu7VYRS3eUbIZVh/01scfqQG6L1c7aoXviEtQYjtGPhfLYC0Y6W
         fwpLITcRlWTgIOseAN82IP0qpS5gASekqY3zeeBON8lArJahiIwvZUPj1Os7Ha/94rsN
         mhePYRhXL6kCwn3ymwfASPGryKgNDsp1RqasmnmBmQIcqFPrrQOx7yOsfU0DYRIEy/XC
         cKSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lMDT/Rx/80y87HsXdNbwVVSl1D9aX42I0Ig9/NpUJss=;
        b=uV6CpCLKntdDdaXdIixbDsv8IZHRkOgFI9qeUzyMCAdPMLXNkiSLeJnBInQg2WkIef
         kdvC98O8bdZksnHTw80A9dhaLfRoNn/t93nDcllVqwfAM/D4hoP56fIarPPxZCKT2Cdj
         //A/6ysmI/dQZt4sGI9LUKUPYsR2+sFfoob2GVgSo7P3SFDgl+W9rNwhOfnS22EZlCxI
         WhA8JdlrTOVWJ8G7vvWMWDGpl7kYuPD+b74xTJt8C7mrOQLXeBhVu8+L6NTuj7rRkIjQ
         ISykzqQfKunr61+mWqJv3U8FN/vGvQaSLxMJWX2Xn3mY4eaOOzDeitnUIU1+lPbY3T+i
         IKoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lMDT/Rx/80y87HsXdNbwVVSl1D9aX42I0Ig9/NpUJss=;
        b=PvCahj/wQCCG+3kB/U7JnxqdYBrqx4r5NRip6MutqOOMf9tfROIUETHyn6IP6kPUCe
         aVlDr5Pg/+yagnLLAAgng5keY9bs8zjC90P+e5964GXojjlkjho9cKqozN4huYG6tGjm
         p5+CacmLrvgiWAiLSSVmsN2dHZt1xRuKuRhSTsitUmQs6TUqIouEfvFXF3o37SCboYLR
         XmHrhPG62kC3olnLcNZjJAiSjVHuef0Wv/CeId1F+YuJscEC4tqwph4CUnKXa1wRFTap
         pu80vRMkRCxlIPMf7k+q5aVjwUwSCmc+0wkulQamwGWNFQ6WzcneRpKJDSv7O2lTmnmS
         ASVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lMDT/Rx/80y87HsXdNbwVVSl1D9aX42I0Ig9/NpUJss=;
        b=V7Nul+RAZ9BUC49zp4bqMaHRGtMie8S1WfAtbXv0y/CfWXuT/ctfyuQ3U04OCKP+CW
         murOs6WhN7emnSMhBjYgm29twThpGejuk2O7AYnAwRcOZouEtFqPc7eXsL+yQ+ZGksOI
         /oqyuyhRwVb1CqQWLKXsq8xxIgB+g1TqCQXlZxEvJvdao9YgVAAgPsxSQqTJ+KhRR4PP
         QyWWxJ3tI/3pROna3SbG/NLJLtN/H/72B7pMwULk33kJR5a1P5ExMrRGZVu1Ukx5dFvu
         3ZiUUzQNbTeqqe8ogjrbrkKQzdGsQ2JqdfJs2edGDqVsKbu/YIzI73J1jvhhzwdw42Xu
         9FaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaakWRFWxG+wu9JzG2vpwbY9SucOgoegeN4vJaScrK2LGJTbGJi
	4CI3CHzhieiTFtFcsF4GxOg=
X-Google-Smtp-Source: APiQypLdcDLAYzxk+upx3PnJypAGY2TYuA+h4qcHIEXN724+ancVUMXrMNTO7x87c1UWWuosxejo/Q==
X-Received: by 2002:a0c:b182:: with SMTP id v2mr20788612qvd.251.1587481589873;
        Tue, 21 Apr 2020 08:06:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4a74:: with SMTP id cn20ls4617973qvb.0.gmail; Tue, 21
 Apr 2020 08:06:29 -0700 (PDT)
X-Received: by 2002:a0c:90ef:: with SMTP id p102mr20264439qvp.248.1587481588788;
        Tue, 21 Apr 2020 08:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587481588; cv=none;
        d=google.com; s=arc-20160816;
        b=eLAQx3tw5B3+7/r9VS+q6MPEj6tJPlxLcgixZIn1B60/g3z5ZF5R/uBb7nuHbQDuvA
         C8otAZ9lz5UC/TjdID+EtPQSeGFkZkQzWmfUXZvzspSVv3J8NrUG/VVUNidlkF3CtGps
         ZJW/jPEkw9KvGwJ+KJGtNMIGS4O7kbVegf0hhp3MiPoybKxMi8fjP1cRFFrr+sTci+2h
         zKeU+bL8Zywlyah9s5I6QqwCnx58/a8pc2EMzsMYcn5w/TRpf5EPFxbILQhjE2h0Mfi/
         JCKpZmP/L9siVaVy250sNoqEEaWF7rJbxYy9Pzh+V/fc2lEImczIjwpVn/MIxq2EVxwE
         Qtjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=qRxtZ867V7TjpQK/85ojdld9hmA0psk8GliIrmIiWg0=;
        b=pnZgdgNpgT8Dt8ZUcD+ouBl47oW2QFqKz1D7His/MxP/3EMBi/Mc6TRX9ci7fsZAU/
         bsGNB+X1wxUOUuik8FXmzoDTCXYqClYieLhSQabcQaxoQisSlQ0Em0OsA2J1FbYFj+i2
         7HKqFB30to/kGOKYI4+ZshztH2xMUwdLTXeGDSB2xJUOectbDxiYQ4HZHy2oR17guZ0C
         /NlILh5Af4/PKg0s0+tMYpHvMdR59IvuwR0hhWOiHdzCkN5Wko6+SNNxzvhqUm0+W70T
         njCbLzQWWz8SIXZNJDeD/s4AuyjfYQTeJn7LB5valOsW2459kIvWW6cennGWlVuf/YbY
         U5JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 140si144722qkk.1.2020.04.21.08.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Apr 2020 08:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 21 Apr 2020 15:06:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203493-199747-lpxScHH7bA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

--- Comment #6 from Andrey Konovalov (andreyknvl@google.com) ---
I don't know what was the problem with global variables in generic KASAN,
perhaps Alex remembers. For tag-based KASAN, I think there's no support for
global variables even in userspace HWASAN implementation.

For stack instrumentation in tag-based KASAN there's a separate bug:
https://bugzilla.kernel.org/show_bug.cgi?id=203497. The compiler supports it,
but it was never implemented in the kernel runtime. (I remember trying to
enable it and seeing some false-positive reports, but I've never debugged
those.)

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-lpxScHH7bA%40https.bugzilla.kernel.org/.
