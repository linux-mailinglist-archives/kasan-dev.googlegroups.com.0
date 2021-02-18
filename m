Return-Path: <kasan-dev+bncBC24VNFHTMIBBTULXOAQMGQEV3AFEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DE1731F075
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 20:53:51 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id g5sf1661916oom.17
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 11:53:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613678030; cv=pass;
        d=google.com; s=arc-20160816;
        b=TszGhsDUb3T7CCNPiMIKdgIFxzpxT8h5hYOszDziZLUE1YWVAsuecmQTvJftfq4t2e
         A5Uwj5ZkoPqUyca9ySsFeZANYQ+aEN+BdrNKcox6SlYCM87AqVmiMBP2onmypwLj4Sys
         xsSOHgYKeIgYO2T/6fk5Jv+loeu9aKIG+HABkOo7uuuKYkXtocPR5ECzNNYl1Ss6Cdin
         1ABxN6tbZA14i0DJLCw0PKlhKSIYJM7dCmLT0WlQs0np6Waxw6QWFqJ5H8umiQQ1e8oW
         OYfP0yp/okShkVlOZCox59naKgeH4sp+73S7TguDez0BbUZ15y4VAIK0datCHHeBKspA
         vDTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=uBRFFtM8Q4OyBb/vTiFPOv087M/EI7BcCOxAvmYGdvg=;
        b=n1N52DAHAw8lLLYMThLiIzqm6kSa353uR0ykuCkN6SuB97yvQSvm9W+wGNdo3ydUTK
         UCHFXp0k4nFYN//G3PXYJSjBKVHz3WKxAbe4euYSs2tWCK5tNG0NU2caeYIc+hU0ewOT
         QWliej+fraXA2nS+rGXZcBJFHF5qdweKJr4zNm6N8JOtX1hKqdr2l0pt+Vpz8k+9gx2f
         +T7U9X+7cwgXSIUUxAtmZj3vH+mO3BmI9zzngCctXCpymDKu4OShwf61jLTH2toxEViJ
         4sApa0OvkGRrIMh7p4TqIboudD+y4T0yGsdyaWHj6NDnRZDd+J6p+PBdWqL2xrrmdW4w
         9pNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=km8eguyz;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uBRFFtM8Q4OyBb/vTiFPOv087M/EI7BcCOxAvmYGdvg=;
        b=DwzrZg4yzjWAZnJXBX+LE51AUNe89yik5cJN9dgmDj+EPtcquN21/Qji6DC2bU7/He
         Jnt+jd9bCg4cmgTPFM0cQo6i7ivnLXtFHeROAgZrO2qrCvnVzNKsnBUgRwPqQ99gsMSc
         txyRbXGTsoZUkjJOMrI5HYpckj8WXxj0hX7lmBlfDqB1gFmKbP6RXaoJQk8ifkhDnW8G
         SLWSJSU72fq+K6s93mizrffNtX4b8EKG4EQpciQLOHHyCVuh/ooDhUdviz43bADcUTh8
         nHM9dYwvhSZmIGAML3L+68og6qvSBFfoZYYNDPWxfY8KJCZ8P7aIJfYM1F/7TEDJaE3v
         rZKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uBRFFtM8Q4OyBb/vTiFPOv087M/EI7BcCOxAvmYGdvg=;
        b=gw2QdK2wS5cITL9ZwkWLGBIa5UnpjRVRPTiMefDm2Kwf429kT5NqKJMmSy6WXzqeum
         2UovjkfdFClyvAymXXtA0/BX3Up/ZHQ6zSZ1zcADp8TAX9xJumLy2wmSn9P86O4QAXSj
         Djt78chC3GVZCMAu3rh6a20GdniiBCCkE3B9d1rzDuLwM76lehJraVxh+OaXAICWWh+5
         LLaMrc5+KPQxVN1zKfPxutdS/yCJ0FcpawAvjxf/vJ8dRFEui/vs/MDYWfr/bwX1ruGI
         DpHSdLO7eM2BMTR1OJ+IAZn1bP49Ld0V/laXz7A8BeoCtMO/QgvgCaFqqjS7wWnDQV0t
         KN/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y+udpNkhFwHs/nXOprqujbDKA77+rTteATlzVEul8D03FnlYz
	VTphujdeHIGbnbt2s/HWXW0=
X-Google-Smtp-Source: ABdhPJxoVfGi/l7QnYpzRIx+pRv6wFmx5c479FmmUDC6S+YlEiLOmVj8i7EtTIzoqx0uMpn/cuI84Q==
X-Received: by 2002:a05:6830:24af:: with SMTP id v15mr4403498ots.220.1613678030462;
        Thu, 18 Feb 2021 11:53:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9243:: with SMTP id g3ls408675ooh.11.gmail; Thu, 18 Feb
 2021 11:53:50 -0800 (PST)
X-Received: by 2002:a4a:e14f:: with SMTP id p15mr4352099oot.25.1613678030154;
        Thu, 18 Feb 2021 11:53:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613678030; cv=none;
        d=google.com; s=arc-20160816;
        b=RvoQA4UpUtUnSJV3pVyk+Lniqzw/Op9EGVmCObV2359Tse1Qww1RwlFS5qKEl/iOnR
         rSKNWG66Uq+nwFqR4SFYrMUTOX6puANQgoC/TeVkz7c20ExMzZaTnrarI0Uw714FOez8
         X1c+T22NU1/T4MrxJsGLx2MY6bphmjAJMFLr64dLkDIsHMz49wKfB6szQLtGoFYhLZHN
         k07CPivTyEcWSkLUfWHmPJk8JmAdldVSx4fuoFBliJjSl27n9i7NjkVIN/3vPLzx4Eq7
         xNPMKr7pVFLjdUmHKScRN0H8kr4AUMkGMVPPO4LlXQHeCHAGCjj4Hk4gLRglzaURduKC
         jXZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=etTQ+LDlPgFtaIkqsjlg6gFnoE3CleAmE5OwVpmx3Oc=;
        b=LtEy+ZFusznheFKXptTTNEV0c7VAtRdpynp9uMMnFjVQuB6KjI+O8YpgUTaR2PW/dA
         tDTsqXwMI1EahF7R5MhqYjY6HafqogUYFsxv/LO43tL3efCaL6C0eSfqpV+SO5bMayBQ
         Tq/80WndTgLhceZxnd5wOervzEYj6bGD0lMm6pr84daQK9Qgg0oeYjhnXK2O1jaifCJ9
         6tl41by8uipjv87G7jLulXCMQTQRvhH3WMMs7K0VZsSo8/PH4ke9BZVcMXqmeVG6Wttn
         oYCpX492/d2ienMEITiGjSeTcrTTvOSMe6YaZX6Lk8eCgWqpfvk55EwXkFfDDDmBr7UI
         oeug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=km8eguyz;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f20si418398oiw.1.2021.02.18.11.53.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Feb 2021 11:53:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 115586148E
	for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 19:53:49 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E871F65307; Thu, 18 Feb 2021 19:53:48 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211817] KASAN (hw-tags): optimize setting tags for large
 allocations
Date: Thu, 18 Feb 2021 19:53:48 +0000
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
Message-ID: <bug-211817-199747-OrXxue2NXF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211817-199747@https.bugzilla.kernel.org/>
References: <bug-211817-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=km8eguyz;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211817

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
> For MTE, we could look at optimising the poisoning code for page size to
> use STGM or DC GZVA but I don't think we can make it unnoticeable for
> large systems (especially with DC GZVA, that's like zeroing the whole
> RAM at boot).

Suggested-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211817-199747-OrXxue2NXF%40https.bugzilla.kernel.org/.
