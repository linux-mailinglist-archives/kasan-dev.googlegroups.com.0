Return-Path: <kasan-dev+bncBC24VNFHTMIBBRXRQX7AKGQEFSGDPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4296D2C6D1C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Nov 2020 23:08:08 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id t7sf3037476oog.7
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Nov 2020 14:08:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606514887; cv=pass;
        d=google.com; s=arc-20160816;
        b=hWqI77qiMAwcKgGassI5i+dQWqb0b8+lappWAMXKud+X7d8TuwQ1huOhJpCP1ZyYY5
         7nJI81p2WHl0csSutXFE6RnvCWePgfkIpCWLdc1qm3uYfH8ejqR+7PHDm9EutTbNnOGe
         alEqpHYQzfAXJbSvngUcV0QFSDzm6YQVYbY5dALBADoUSiXCZxShIz0l0ApvkbeKPWSu
         qukJyW7sgnq6YTG+aNNAMGjlRdqYuLTcgwg/IELrog1dwMm3a7zlWOvO4OHPY0wLJLd8
         4kGrViOcmOc6RpyzxmNDYRR22rQAFnA/tzxJ8NVq+eq2bhAcWSRp5Ed2r9Y+mWYrktQU
         3CRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ugOdT/8VT/0YM23s4mLgjUNTc8fSEVqiF7eqBOn6ymE=;
        b=hcXBJrW25oAEkj3jljCs3ty70QBtNrBGHH66Hp7ThpcT6vK29j1djjHO3cM5IlHB0h
         vsUGtamixvFQ/9HJcc32DLZHDjI8o4DzSzCNViIJuioS6xnsOs7pXqcZ2MQlKY8Ry9O/
         sdvzrPC5s3vCDMJrKYGDryMEK0186+NNa1FgJEQ2NwpYd0572sjm8Z/YDNjv3IbDF6j/
         4OW1ezBcLzqe7cKz+En5BOlvQrKxpl5bTTZEITBGC++fH6AUwEqLSD6Av/fjKtguQjgn
         lW+jrv/K0cktZCAXC+KZHtPXHlWo586g9hEfNJVSQ+2UjV9Sp0v9MWuAV5tS70HeXf74
         qkvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ugOdT/8VT/0YM23s4mLgjUNTc8fSEVqiF7eqBOn6ymE=;
        b=H9LIBlTFDLQRAJ3AdRUByeEN34S0uf0K5MekLfJbfwiyjO1Ql1e2AyvtTPVv/MD0QQ
         UIf/Po7DSZVsb8Kg/V1jvu33+mRdaDKaTRyIz6EadLzIDj/meLgz7ytyGQwrELVyjZvQ
         6PBUjPYH81KTDs8a5V7F0o2wM3fdtPqOxH3PNz/dIzA9xklHt/BXX9SJmCtCXFeX2VMC
         s3B4jR3q8WKOW74R0KhszqNgOBEJSb+IQZbZ+c+wsUtLEJhBtYaLGIcrlQzgYEpJTT8m
         NlZEwW0rpOyFbTWMk1CWcVDAzBhXFunp1JR0L1gGJTL8SbiZHoXhaVoyc1p39ePV6sxy
         MeKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ugOdT/8VT/0YM23s4mLgjUNTc8fSEVqiF7eqBOn6ymE=;
        b=ZWATulm4ez+UmEKhr1Cp6T5fBmXFtKiXkQWk/15rjDcgqD6joMpe+Ues+7Zgv1bApb
         hPerYsvjrvO+LrAZsX0w3U0DnDGsOJDpQbKEK1+DAc2STBy6iiSIgGkigXKll99NG+KT
         d8Bp4V3KWlMvGN4emrBWaCyQTy2TWIGcOfFYt8n7nbFe4clwIQhgldvsmKEKCKmLMXQ9
         QuD8TvyLMm6CWxRrS86dMFU61hZ6pIZb0oK08mukV7CVY/0AhWPIblMVlksAXmBhuji0
         BQZOYz/DIBzN81YimieOvNCNdOppYSPf/RBog76beGKqPLHuhDEOGXRg28hn2qSGWPpx
         iKjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PclAbUMAd+VL0IhEANok/Ae5ZluXzIrjX3XiRhxBUfXC6ANc5
	8HNHoUXRV5qxkvhaZ5WseRs=
X-Google-Smtp-Source: ABdhPJwVplZaRmuxgueW0uxVwImCQQ8yhNUXdiFT/c9732Ltnm4Z2Ltmr0Xt2WozbU08dwf0XkjL5A==
X-Received: by 2002:aca:ef03:: with SMTP id n3mr7025345oih.75.1606514886910;
        Fri, 27 Nov 2020 14:08:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3558:: with SMTP id w24ls384769oog.5.gmail; Fri, 27 Nov
 2020 14:08:06 -0800 (PST)
X-Received: by 2002:a4a:91de:: with SMTP id e30mr7505962ooh.58.1606514886625;
        Fri, 27 Nov 2020 14:08:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606514886; cv=none;
        d=google.com; s=arc-20160816;
        b=D+vclkCDT3OSk2i1VgEsJfg1MXJecuNo7ZqBJ7qEl1aBriViI8HOQLnpPdy72BuYAz
         B0s3sbkIPPhl42nQS70GzpkqDEDFatoRK7uUIiMgcOCpHCGkYc6NouL4RLC0IsLSmdq4
         Zl1iB2YtHEfZu7H9YsJ5CE7qbbMroAPm/DL9pUuB9z4QCoITx9VBYg2oEjHrmVe4OHXC
         kCrRw2wUYZ3BS3LpR4+wAT4Q++yivMZ0xZ1uDQEFKxA1gSjuRGBOXYrfpWo0Y6G+BdO2
         zvmhM+clobBYHcLCw6FOnmfbf1qKpp6wAq9QJV5a7klbBthTSkkKY4UFSGb+gPE9f37T
         s0vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=XP4WF3hv9plgshdQOJNe9iEZyUZgBi+ouOw7UenX/LI=;
        b=GJGQlkjnpid0egdHysn1f13IeyaXPiulzAg16AkOzlDi8d+3vAORaLqzpGdHqgdwXY
         E3ZaJeHiCpHYbDPBqNsJmLIGSImm+iYCvoG9oyRdIin705tZHrTZOwt0C4zUQgAIFKFR
         ITyALsf/f09aVLb3IKshVaQDEFQXKKjvlWWQGFkfVStNsZB1t9HzC53sJt5Yk42yCTHl
         U0QEWcLvU/r1IKrDsXIVm861uznB2ydTaBa/KTKTwqpaAUlaxnQ5L5N/gdv7vJ+3a4SV
         OazvvlAOissnM2VpTyRpXJQ9ikwGeetliW597/xNwzrClIhzH50Saj+QDSwBGXhzmMHX
         o8HA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m13si515809otn.1.2020.11.27.14.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Nov 2020 14:08:06 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Fri, 27 Nov 2020 22:08:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-210293-199747-SgH54YOrYI@https.bugzilla.kernel.org/>
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

--- Comment #16 from vtolkm@googlemail.com ---
Created attachment 293851
  --> https://bugzilla.kernel.org/attachment.cgi?id=293851&action=edit
unbound reported leaks with line numbers

leaks also reported in connection with undbound (DNS server), enclosed reports
with line numbers

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-SgH54YOrYI%40https.bugzilla.kernel.org/.
