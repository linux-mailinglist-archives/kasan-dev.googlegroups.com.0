Return-Path: <kasan-dev+bncBC24VNFHTMIBBMUE5KAAMGQERA7CXUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B396030D805
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 12:00:03 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id v190sf4270421oia.6
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 03:00:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612350002; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJSphq6Dai5lvo4Z06kOg4+5/oeCInSSvE2p+LlGUBklzgwE+XnDppiEiy6gFTdlPm
         W1ugKf/DPtXJ1xuk4GuMb3THeir0SaO8vDzdGBH9WEdU/55eSFVWglpOqv0a4qbA7nkp
         CtkTZ2XBIKwp983ZGFiHODmwE+sX3uBavSvqMlnVVQZnuVyRO9vJ5QBbBwTO9qvrnm7L
         JnHBcUMg3QU4dDy6ZqZmoxUZcV7SbYDUAHnI3QrAIDtGCeBcy/MNTAoTpBYkT5GJ6IRG
         L5a5Vx705JcKbqOI9vD06+EI5MkldMS6Qcvq26mSZheuykgJ7hBjPn/gTNUQURM8VVXq
         tC0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Df267SfygsufRKzd8pStGP1So4HDsK+zmUTdvyyPN3g=;
        b=YhyEt0yTOxYabE+4Q1OnHEvuuYBFVeknCLfECa70tYiYfKT603Pw5VAsTvFo6zHqoW
         sJJdhUnfeJrMhsAFlducemGkSfE3bfUyJPSGR8gZKrQgu2oCrJONe+2mUMJTg24Icuvs
         VVmU8hQIlK5MJZw4a5aA04sz+pCcyjhX81rhsd4JiUHGryj6VA3G/Ak9YysILloUTMwO
         PFc7Yd/oIbUZDTUUADT61hnm+Zh2qkp0pq3rhYD/tgZo7lm0okzYEL/FPiinLqdWRUsd
         c1LlJ/UkpVd3sXX3K50QE2ur0HcYXGn+gjBAf0Q2hoTYweNG8zxOnmkeJkCtnsSrCxNn
         r2+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jnUeLn53;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Df267SfygsufRKzd8pStGP1So4HDsK+zmUTdvyyPN3g=;
        b=fOtto/c+aFQlgX35+eZQM+K2lJR3XRwfJNxYsbpdW91vOnVqoounMR8lXN65seJiHX
         b7V0I9NgQhicdNxHTT7AZ4FY2FsH5ewYKJ5IHCI0cu1M+SGw0SYg8vBSCwg5rYsecgPN
         iTtNw3j8DalXPngI0OoH5yyltdRqAlDMgMOYdjRqea1luX0b0Eq1w1K9vZRVKA+uGW5B
         cUGlFOsgDLIkztrau9KHLXxzqc/Kp2kTpjfQAJSfKj55j2hQkOkDlHXDfm3cmKVjc6yQ
         KQGIK2NQt3EaFTG2ZldQQrs0Tak0bsHrUW4fJptmwDYEjjT/UWBc8WNmdJ85ogoXNfVm
         uSfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Df267SfygsufRKzd8pStGP1So4HDsK+zmUTdvyyPN3g=;
        b=E15xntWdEgWCQgcGryQY90efdYQny0gPzC3E2Qu2tiWGyZsWTfriIE/8dgR0iVmxWK
         QS6KIHYhyL2RzId4pKCj4SSLvBYcm58WvR6kb0WAoJx8BiysKeYSLKpyrouSerKfjBcP
         fPP1mSUCQ4e3Gry5O1RaXsrzq8gOmq8obNUxwUddQooGT8yCC1Awu+qhOu6VNCu1uHO0
         AbN+1+lshWNCkA/oNOcxmRD8ks2irbfoutSumz7bJmQrqZPdL/wncjhVgqzkQquq/uEh
         kzVf55w+FRoIdt92V96RyI6BcqWQHhoETqXMNiwwcAO1oU03MtLbZuLndR38GnBhq2Zj
         Cc4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gJcN0gN86yDQTILEaQr6Uy4WWwlnqCFpJgjwRNu8xeFfGThvk
	bZomaVi2+2VK8LqG0HZdQSQ=
X-Google-Smtp-Source: ABdhPJwUEBHLJMo2+/7rC3LtDQUlh5Rqm7KY0mtfN4DlDi+pygRFsBp7Xds1i/AmYlnwrb9VykRh5A==
X-Received: by 2002:a05:6830:15c5:: with SMTP id j5mr1655004otr.185.1612350002349;
        Wed, 03 Feb 2021 03:00:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b489:: with SMTP id d131ls413823oif.10.gmail; Wed, 03
 Feb 2021 03:00:02 -0800 (PST)
X-Received: by 2002:a05:6808:b14:: with SMTP id s20mr1608058oij.24.1612350001970;
        Wed, 03 Feb 2021 03:00:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612350001; cv=none;
        d=google.com; s=arc-20160816;
        b=sShftUBPuDYwcClRHS3SvYvaKX+qGkhD2kXyT1kfwSfhQdPwYlQvR5xSBPmN7so2aB
         PhOZBM+1CceFyPkPFWpjfsOKMRzzbKD8k7MrI3qQIqNhmjL7c0eWwSOXCRsZr4Y3fMEi
         5KuKNL5Fl6cHM3WW/QlpiYfB9DCs56VUoDhDmgRfqDKaK3i7HK88tnCQXb9SSgqPg7Ay
         iWwsm2oG798Y4LlLh6aMct5MvUHBxCkByNYB3oTVcRsSJQfECqX69zX6bzUpAGwUPZDV
         hJbLWKZ/0yhRuvxyz2TJqovkqqXaq8ubvrf2flBnk3TT3jpbGHzZ9Ad4eEV+ku5QRNxO
         q1zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Kekfhl7v/5CAP3QL7p27eebAfjQ9RAMkXlQX7u5BEOQ=;
        b=nweCf7jcjR2pEVgiagi1eFOY6rE6TgNz8YwMWwNUpfYymEqkrET/irOHpQce0+p2vi
         +93+Mf5dHduai5EJ1v5nNVWhtEX2mXhol8sqiyPgJJtO367Q3cDsr8k8vgPxX5hQ6Qdj
         zYVvvr/qESQ4XgIRa9ySRFhdhjbj1ShuJ1frklYCw1bcj8dI7tTRJgfkqmbw7yZv+Fqe
         iAKJb2T/pZzRr/gon/qDcAPoOXtP/n5c46TjXEcnIe/68rdDyhZiQUEAHILBGPVG1G8s
         XN3ofOUzucd4Cn70Ldu4kc+rIep0u5LFTFsZFEVK1XRqWXZzMyee8fFCyUbEB0f3COHK
         R4LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jnUeLn53;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b124si103319oii.4.2021.02.03.03.00.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 03:00:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id E058F64F5D
	for <kasan-dev@googlegroups.com>; Wed,  3 Feb 2021 11:00:00 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id CB4B96532E; Wed,  3 Feb 2021 11:00:00 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Wed, 03 Feb 2021 11:00:00 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-198437-199747-uV4mCa6NZR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jnUeLn53;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #9 from Dmitry Vyukov (dvyukov@google.com) ---
I think this can be considered fixed now, we have support for RCU and
workqueue. Works like a charm. The credit goes to Walter Wu.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-uV4mCa6NZR%40https.bugzilla.kernel.org/.
