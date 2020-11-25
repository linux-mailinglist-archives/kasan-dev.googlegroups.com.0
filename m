Return-Path: <kasan-dev+bncBC24VNFHTMIBBPXZ7H6QKGQEGNWDZOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AD372C4459
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 16:48:15 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id x17sf1970915pll.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 07:48:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606319294; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkwburdFkAB9Q/Ok8g4KdMvoIGDmMrrSi/ETSB9Uj2M9sqKg+MJjtnNLZRHs5+uYgc
         E+o0z5YMAra/6soiRIFknvlzPfOHdmKsOTccDd+5S1wMHgdePtBmMiwAi15/C7GbvDLQ
         ZjQIlF8/Mxc6tzG4/BDgmy4SM3OUGPX59EQtS7BDoTDwEi4/NScPHJ5fLAutW0vZfS5J
         P3dPTMde050oZkwE3QvUi/EWaq4jF4fAll5xxEs0fxPBCVTt2XpCr0skW8qFnhWXrcZL
         Jm+ChWjvYRuVr2aNqtkZdujfQ79KddZPx9/WrEQLZ/BoWTtfZlPd6RhJ65l4es/i3lFo
         wG5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=OLJeSUEgvksjtWDDEQ9eERXEIO+KOa/lDS2jBQl6IGw=;
        b=n7su6tGrAlYlvKv1hmamiECQ/RvjQ+iHzMiVGEJ6U4OP5kGh3jIGSb283hu7bG4O/3
         XejHr31amjzOeSd/8h9GWOEPHi8u/hRlzC4z0d6eHzcn/0GOODDz9z1QYFHnvf/udjHa
         iQmDPpi/F8xYP4gdRqeHgs+VsMDyxjm3a4bXQWuvAdlr6/9k0ecsn9sTuBJMa+K4g9tm
         4Hg+9OfAsc12n3EZyGmQ3vpjrhWOK4Mvp54tgu97grnWjurrKAjfeoXx0bco9+XxWown
         ozZu6fVIDqt7aV5Yri5noKxhKUQxAwfc7RLrB8G0KRq/ImnnvC+xSxeY+jw6LrQ8wFnr
         nBSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OLJeSUEgvksjtWDDEQ9eERXEIO+KOa/lDS2jBQl6IGw=;
        b=o/p+y+WxxYLmnlQtHdOIUOVAVb13OhQE/CUFAUi16rRfrYIiaja6+O1NZBBqdCeyMv
         tl2RchlJZ2+a1ArOBOpkYvJVZVReu31bgq5xxyPkquGiPOD+JcHe+8sXuf45WXR8uqYz
         CQwF+xvauNimNM/C+ae3lc6lT9wyaju+NMvXBQsqhD4Z5TMWRRVBR9yblrQW2O+crZA/
         9I7TEw6BI3/7iU76dNZ1ESkwC8CCyIfShpHd64xxBDuo/F2JRft6YInciPHLYWzbpGp7
         SFA379zhICJe4nBgBCK0u9iRIz9cpoWZDAJtijsqz2HMKAK54KQTIA14IeTiUSeHavRd
         VJhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OLJeSUEgvksjtWDDEQ9eERXEIO+KOa/lDS2jBQl6IGw=;
        b=FASXLPsmmWNI9VMnnoY3ErLUPTFm+nRdoi8Trp13mf6uP4cOGHCfwZVMFYauY0xMFJ
         FaDNG9YUCd23gd6uGqjqG/Exl9+sscrdjgqoidsdh0rgM7CXNYQPqel43U4gywhz88WO
         8nQPT6e9/rg76nObmRCONlK5teltFIDa2ixo6uCYF/2DDaLRoPHtJLE/23PrCns8e/IL
         vfPgwLO4m3JS1aB7G5NVIGqg5I4yDtSP345g42Q6jfV+zNzIJKUsbPQ58/m7PHbrNG71
         /xduEE5hLzaZjNi441r6eYG9JiWqMdyEJkqhjUcpR5FO4pbnGCBRnj5MuYfv02RNanB/
         aR0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+Wrm/3Uj0Ni9kmsNIJCp+ap2q0L7p2ryon9Do+b7HH2m9up63
	R5/zOwEeuidaPYPx5xgQVF8=
X-Google-Smtp-Source: ABdhPJw5gVXyzXMQJ+7ha+rcx68oksgHYQMRsWfn+jtSoY0Rsyxmil4tVLq4+9kgjUuxafKV9YNK3w==
X-Received: by 2002:a17:902:6947:b029:da:1cfe:8aa1 with SMTP id k7-20020a1709026947b02900da1cfe8aa1mr265760plt.47.1606319294126;
        Wed, 25 Nov 2020 07:48:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b187:: with SMTP id s7ls1251221plr.3.gmail; Wed, 25
 Nov 2020 07:48:13 -0800 (PST)
X-Received: by 2002:a17:902:9307:b029:d9:d097:fd6c with SMTP id bc7-20020a1709029307b02900d9d097fd6cmr3558648plb.10.1606319293633;
        Wed, 25 Nov 2020 07:48:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606319293; cv=none;
        d=google.com; s=arc-20160816;
        b=t5/c+EgKM0SIWOURUg62FlQi7Tn5884OS0/I29ly/INvPkSAxx0oxo+mSlvxqR3aW3
         3htoHdsyZgxoCbevrELkhRJmJqyPe8vVtZaVdmNBM+yTLOmiw1zjQB42BWNgThOmYthm
         IIDXzYkUeeICWIqyj+JhlNBokUr9+eCr6yVBI/lBGrJKwUdhCmY2TvpB6iuK7DgJkcYT
         FNuTna3mdBsW0NzmyVhCr2PB119ppY340toQDml5SLtWxCLgnZP8/TjdpTskUn+Qp6+v
         sNQ8sGHvifj6JY7Vw4TILWNWPCJC4T55xezzytc2PmMwfdTnJENpRZnpEGcHLk3bo5Wh
         pVSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=lP2uw7DwS4SXmuXYn6Paudy7dbH/HNDrE832DFTSv5I=;
        b=rfSwDfZiCqjiadtOchuClTB0AeRs+4H8rEbow43wRQgS605d6CivXIwPlyKovJgTeb
         GLBJ4qTgscJj3FLAh4MPOERXiVSmmls490GZ3UJTVCupcFwTFmyppcLY6xKQVV7tLBCH
         lkuwdg3GWjvfyDMau/TbyAvuNknFNosNqkrHRNJYB2tYgtQRfuazhMGw9t0OjLWoV86c
         UrDcDU3XX7uFhG2V14Zi0BMG715EHjitreW6iAIP0TROzmdAU7rNd+8QmD0dQ38iqiwy
         G3qAfs37+/wIpG8QTavEfNWxCRa8KF/Z424xypV9Ea+HCPXKa6KPyK88jgOp/WoXXqas
         EsDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v12si8688pga.5.2020.11.25.07.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 07:48:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 15:48:12 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: kubakici@wp.pl
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-0sc7nMIWef@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #7 from Jakub Kicinski (kubakici@wp.pl) ---
Why do you have KCOV enabled?
Do you expect to keep it enabled in production builds?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-0sc7nMIWef%40https.bugzilla.kernel.org/.
