Return-Path: <kasan-dev+bncBC24VNFHTMIBB6HV7P2AKGQE6EUFE5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C8231B2893
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 15:54:02 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id e3sf9749581qvs.16
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 06:54:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587477241; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkALOlrJe+0+EvHhpJSJ//wV0j3xJIRM3md6QWznN+lFg6duCj2/ICKYbFuWgCKhcp
         G1QvswKdLVENBE94VoTX0aYvaTO5QXmfwE4AQGMJnFTih+XsEW7X1JIhRg/zaC7NPFls
         rMUcNbpT5iac/TumXwa/Qv/Z8jV7G6traAuU2EmpkSr4a2tJSJDrXFk0MJ2INXngFz7W
         7JIJuMEehaBjmodGewdhRtzYlKU0DXrPWpDvWofDlnb6PUpoAoVPVluaXhHwa/DCja9Q
         LUDPp18WUJcNjQML1M1n9aM+OdBdkTT/zrSOCNMKO5sWwBL6jdzRmMeEBaigN5tMcfkP
         XAsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=FFnxIv/j5s52AYQ3WNjUUmRqzVU50l/0s0qIWjz6VzM=;
        b=UTZ5RTVATGaF2o/o8xEjf51zF3s9lVMnPMLuXeD6zpkoxHkFoKmnOkMMo2+3VDaVTM
         vTU8ujUAIFczP8wnGQ1bxz3edOyaorNtdcXGWdA0sG+gZnPLaTFFjWATcTA/aOWTmN0a
         WuIV5pwsVVxFoGdz4IOk8O4h4pTLF25Nk4JMLM/aFMFCGFKRLP/LSP7lCYx0me6zjgpQ
         gvmQBHjYTszR03DR9G7eYy4WMWsqCbUgKSraYx08MoCHJKvGjizaofRxWirRxBCwLQ4H
         Q1c+KB9ES4vH88FlJOjaVDVHOHmQoxNETzSCr/QVrtasXcSCY/cOTnMjL8+5PYvEzYpK
         maPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FFnxIv/j5s52AYQ3WNjUUmRqzVU50l/0s0qIWjz6VzM=;
        b=GEEMBHQy+hA12YblZVa0UQUuu7FZ1ocqJGceyjyKz3kKsSGkVaG7BvGAbpkGGVmRRu
         slvzcZixHA+G9RTgX4gOtaACTMWx1HwZN+HiCj0gMPG5ytG+CgJHdDMSuUekJr1YsYC5
         7sUULKEyNy7Q1ZmSIei0LDiIncep9h9mbvBxEyxWFaRqS6Ib+bCfYOHyT+rtxlL9p7Up
         TzAZvd15kGG6SoeJQ3NTaN2HT91fNVEjxTbGzCyj0/JBxgIw5Qlqh9RaFIJW+5XAlKNn
         4qFywjRBs8O+T6As8Bgiei6SVZnlBZowzjcSAbAWHp4rncwzW2t712oz44RKb2nVRqC9
         0bSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FFnxIv/j5s52AYQ3WNjUUmRqzVU50l/0s0qIWjz6VzM=;
        b=fKXTyELEVEatwSrMK/0a2qtkVxw8Tvr4Fzg/XsRR368dm52z7fW6d2UirSN/TBXqeq
         Anf6lcBAQwieviYeTo3/gPoynr52gaiS89aSY+SooHuLGo9xE2FO14XowVhwjnsXGaNR
         8+lUXGFrOyO3XVnUDevvAO3xsdfakp7IxBP7+JGLrRMJVHn9UaQBiUBz64nFe1kveclj
         WQ4o2BgcqhX2NhYQuRSHwK7djKey5rqqE0eAFbo3UKGk5om4myPgqQDZ4l+JsqV90V/w
         xu37adxdPOIxQ+oyNt30m1ciSOQnnA7Ok4T0QELu2vl0gZFVgNg3lKw7Bpx4IpgOJZSZ
         zFVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY8Q7uHTnyS2MqfgOL9zTshWjXti5jN/d6zrCli2iz1MspfTyaU
	FdVj80X0xQq06sHpcKzWnYc=
X-Google-Smtp-Source: APiQypL2GqeIskOlBfJOVRobsUGanVNBvrcaC/xMMedfkI6J1X36oFYam0kWz2YylHe4SXiRVwefnw==
X-Received: by 2002:a37:a0d6:: with SMTP id j205mr22066649qke.450.1587477241034;
        Tue, 21 Apr 2020 06:54:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2205:: with SMTP id m5ls6214298qkh.1.gmail; Tue, 21
 Apr 2020 06:54:00 -0700 (PDT)
X-Received: by 2002:a05:620a:88f:: with SMTP id b15mr20534496qka.118.1587477240702;
        Tue, 21 Apr 2020 06:54:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587477240; cv=none;
        d=google.com; s=arc-20160816;
        b=sM+AO2MA/if4SfQKxkAYTZpP9QXii7KzpasqKDYGBLsC283JLTjtMbAlrF6HjLGKRz
         sjBuYd0qWtk7cEmVOfd8FO5PDfuKxGRvmXT10tCEEod09h/k02RZp0YLCpIfRzEpQvUb
         usrCwNnZlL9EWVFECfUPAy0mvNgoGUC2yD8EDULM7Ur6R7vDoEwr6L5ziNj8PnmcBlML
         p/bea2ep3ohUIAo7sJnVTVtcNjsB+mjhm/E8NkCkNIirJdrLL9Ck5A9jiDtosuGXVAvo
         VsyqFP+q0LMXIXem/bYH2XQn+nz4IE5d8jUrsV5wh8cAUV3MSBth+8jGroP4f1ZMP1Ym
         xU0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=KKoE+tpTlFpFtCNma64AA7tMpzeWnTZkbajNrMg9AFA=;
        b=HS8UxCj8ZnSCMernMZqYxI9qHPvBs5cjZwLmNDuJasvB9M/s4KQnYaPOS9vUxed0rN
         YGdBFllhn2fPRqT6metyGd+UiPWxmGXyx4k1RTXmT2/f154ArwJKSOMNC2gc5hj0hBCt
         7eYp0rYls9NUYB58exe0th8l3Ym1jSbUi00MVQRkpaNLGTNd82paWt3bswWVC40tZGNH
         txg+4jyhmR5RJ+1eS72q7trtVR2Anf7YwzzolwzxS8wuG69ot3qKhpZikvkNVeFIbd93
         uKn+WRfws9NUnfYSIO7S1TsxDHYcLE78C1pdyfTmhoQXJqaPGyjccVpVcqYVRYqNcsvK
         f42A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e7si182216qtc.5.2020.04.21.06.54.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Apr 2020 06:54:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 21 Apr 2020 13:53:59 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203493-199747-3x68kdGRou@https.bugzilla.kernel.org/>
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

--- Comment #5 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Dmitry,

Thanks for your reply.
I agree with what you said about global variable. We try to get the clang which
is work in user-space. but it is sad because it doesn't work in kernel-space.
so we stopped.

why stack checking is invalid with tag-based KASAN? unit test has something
wrong? or?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-3x68kdGRou%40https.bugzilla.kernel.org/.
