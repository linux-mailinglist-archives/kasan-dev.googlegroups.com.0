Return-Path: <kasan-dev+bncBC24VNFHTMIBBNOHT73AKGQEWKRKLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id A33BE1DE922
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 16:37:44 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id p126sf11275880qke.8
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 07:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590158261; cv=pass;
        d=google.com; s=arc-20160816;
        b=g8m66q4PLaSHkBIcrW4O24G2akArUBeclFuouc1MN6xV9CDpevliZOAyH+mp1fB0Rd
         AmKGrlkvTd8pjq/+5Gb5Pn0WOWOLiB6K02e+YuV3VDtICIoM7twQRxijozxLXj3r92We
         szgehxDUmTBsWM2ro8BiMGtS93T8g6Q6hcRtsOj3OLfiaSvKeKQgFefOYLqMkS6jSAsD
         cKkAbW8gYw1Ns2sEzk0LJ+nkhx9LmYSyg8kPKMSUNB27ioggivZz4EI52kKQl1a+OlK9
         VnZnmsTSiscuekLBVkD0+zHI+f58jLiKqlSczy8qf3v8tYfkDpbtnZLaSC8Nopo5Em8A
         8IbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=dVUSezuVAEEIYswTywk1LSYujpxe5fMHYHplslS0Wcg=;
        b=NHxmBXr4qbQ9xMiZfdZ/B8inK2RZ9PY8ZtfYHG0xz3o7dGL03X9L/xiXRTWtHgG0YI
         tnNLZY8fT5dFP9NY/Ep6cyqdvtFrso2o5vztBksaYb+dE6It+Rcv+oEikiE1Se80kS6f
         OZA+H9eTuLc++rZPpfQiukU3C7zTGezZeonpJ3Bt1Sz3NhUS4jfIiu30tZmyL+/NJV6c
         9Glhex7itIRVPQZBm+Kd6dMP/WBWjG0I9ohNQziyoeyFIUijVAs3szNCRVYm0Wt/n0dk
         rO/8IZ2FFnW+iRSEMdnuw+J9KGVsbpNEzpmZiVe0B/mtb9OFSU6ej7kqXBsdj0deNFe8
         j0OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zp/5=7e=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zP/5=7E=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dVUSezuVAEEIYswTywk1LSYujpxe5fMHYHplslS0Wcg=;
        b=VYSRkcAJrPeTsrkAZg8rtEGNcJ7X/PSQri62fmAnT1H8x0NnALD2csp+LJYxQiDEU1
         S2aWWPOjzt37VCFyqFw8WcEUWLU3dDR9eHMhrwxNp5mYhzZsKOS+91o4OHjkFeaafcsR
         qpwWe68DrW++XXd5NNST5nHuKLr3WXDrRKeiTbepwAJ7heqpwSUut7CcpsBhVG7kYfce
         d6i45cYjVYlft9FLktgOloPY7Y3HIbenQK1NKmfp/ZG2kr5m91Au4i1SZbLtDpbpMLpt
         em0yztN5xpKlKUDY0/aXMB6O9+J0J8PbR6p7WTCSkoG5M+sVPYAQCid9HUAtw7wRIa6j
         zLkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dVUSezuVAEEIYswTywk1LSYujpxe5fMHYHplslS0Wcg=;
        b=J7B/COBK8t9V5Qy7V6Hc1TV0suIgFlxAhon//zSqwR9wJb7MBH/r0JnG3HwEjEBHxu
         mtpr+ss8QVFqRTeXk1mXjZTQSdihXRs9KSrhBBHGy+GudlYkXock8EN2Cp6PRPKIJOaY
         yrx9AyjTZjHv/e5a+3IonA7ZbOFMlA6zTlprFVvZPWWGV4ziKqHv4B5dlcMc2Q8aq9Nn
         Z0OYfAXFPfrTsL5c//vyW1mv+qClZWiAGvnjV7DcBe0nsd44MxnpLNUguS0P9wgt76rh
         9MSi8pEuhLMz3OrEFoSXMaxD+3glCjwKSH6b0+Pi5AKgfxI5hYR/3jna/VxRWKJ+gmZ+
         HGKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iaSWHGbsXG1+fdOS0kuUyOBhFHfVN3Az/ULlHQJsRqkebEH+R
	RAgLI+8LlIjzyEQ8hf/CTPk=
X-Google-Smtp-Source: ABdhPJygGmJ9bF7e9gEs8wWL/GM1A8g546MFvra+psaGdE3AJ/j85VBqnQgDL+LVM6P7yVonwhnQOw==
X-Received: by 2002:ac8:38f2:: with SMTP id g47mr16133990qtc.118.1590158261201;
        Fri, 22 May 2020 07:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e56:: with SMTP id e22ls588559qtw.3.gmail; Fri, 22 May
 2020 07:37:40 -0700 (PDT)
X-Received: by 2002:ac8:1416:: with SMTP id k22mr15882398qtj.205.1590158260902;
        Fri, 22 May 2020 07:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590158260; cv=none;
        d=google.com; s=arc-20160816;
        b=F/sPIhNOXrqSisHuSl5+Ok2EIPP90i2xHdG6M/vmNBVrPtLvAFdMHS43ENVkQYnkOY
         6KF5oU5EZIHL5IGq9YPpYd3N5JXFlVlhsot5tThcyjMgm9WTd8ww57a7QFWt0UfwTyQ+
         95KZ+xyqB6iGpA1jhUFOW4Omycfk4tHMps1NyNxe4nwTZDx3Vt/UzwXtNgg8EKNjuab3
         k5GFNV19nhp54lFagPgsC08nF9UeZj1uH9/dU2Aa0xyDfoj7cnSix/3Mabu9wKKM0pUv
         2DvFeN02e7GssBZRMOe82A6CqyxG5xQMD7Qd80vlFbAkWaZYKJDfdNfRznGKcOoC8HDu
         T9fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=GdThlRfFdjuDJIRMWRSpiBYgIB4RQxGqy+3qtVCBhg0=;
        b=GmSl3ZV1HK7qQnNvDtKIAV79E0ws0zhXrDXFLxqvTUUKC5Y7rD7lFlO2Snkj9gX2xt
         U4MSMgpPp9Fdou8+vrOX84jZeteUFLahz0dGcgrMoCPjPRl6nX2OZ12CdOlXkfD4+0LB
         TKq0NKwLzpJJzU8CovZi9LjI65VrlLZwlb5Gbn1hrXrjA8FMl2A+JAAGY7rlPmEy5QqQ
         EDUV14oqj1+BcNPOPYUWCRPozqn98DZHDcFz8HCL/1IAZmiZGQoSGILVy4I77gOf/R2Q
         2g3Z8kXdoEbLt43E4Hibh+jQjeP5KCSeM6M31zwUEIcESkkSGmxukci0lPxYK3k6BUrf
         vaSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zp/5=7e=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zP/5=7E=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v73si748420qka.5.2020.05.22.07.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 May 2020 07:37:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zp/5=7e=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Fri, 22 May 2020 14:37:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203967-199747-1Kd423FAWq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203967-199747@https.bugzilla.kernel.org/>
References: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zp/5=7e=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zP/5=7E=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203967

Andrey Konovalov (andreyknvl@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@google.com

--- Comment #1 from Andrey Konovalov (andreyknvl@google.com) ---
See https://groups.google.com/g/syzkaller/c/lWNU99juENk for a related
discussion.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747-1Kd423FAWq%40https.bugzilla.kernel.org/.
