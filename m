Return-Path: <kasan-dev+bncBAABB7PI32WQMGQE3QMKJWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 63841840825
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 15:21:51 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-290d09f47dasf1571481a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 06:21:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706538110; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPdbLRXzA8TZQ1VUlWmxs3enJsfAyqLJH9XZ9rJMAc/PM7qn+G0wfI3U13fDjpSLkm
         qAHZGWmtt9YOf9xRKU6+FFQBD02Z4dRFbNXzoLFFwS66OiZ8TRU/+v75vvnUNkUOIIR6
         tQbgIhGdMYjPWD/x2XLU7NGbinY0JyzB/1v1Iv6ufHjSnB41BGSF79bGZJC/9C38qBt3
         Z9PWiSU1EsE+qCkhqjariZmP5XMW2YcQ8zUmnOcLO6l76L7K4S6vK9Y9PHFByQZkyBA9
         IXCfz7PLIXL6M+oC1AxgDt1wzhQ5y7L8H9S0YQhMUB+NHNKZwifwjoMFUsF0lhYQmr+T
         IPag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=K4Rc7p9PWjQhQvhRCTBPdGfYJzp10T2+fdlK7XpBq9U=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=RDhvItSJh1bTatsstJ7KJr3WpVAcIJ46pFiKs7Sn2MPsI8+yGwlRFR9Z1XYkq4lNtz
         sMSRkFu255nAnDmzHzw4ulhVuDbH20bsW3oMvF1vEtlzdJadUK76lKrOEmi47DV1FueB
         1tyXpsgAWMpUEEG4yn8Z/BNE0XequOeiP3t9QYptrZkeYX1SEtDW9AN7SNs4oz/avyFj
         Dx7OJ4PWc0To99k0zhDPORQ7w7FdLYvUzS1zmB0yTIezdgqvtT13d8c/Lbw40QPLViKH
         3/xik0Pc5VOuVH/XDRdcgV8M/w/6lLnVxob74+eQyuHsQ7301ED9lkIB1OcX8YlWdJRh
         7x/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uVrT1WTF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706538110; x=1707142910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K4Rc7p9PWjQhQvhRCTBPdGfYJzp10T2+fdlK7XpBq9U=;
        b=mjaqnmi4JyfY15LVaOWmNSKjOVVPCoJDdO8y7mfbTRg2OJNrhmDigLaPjmpi0iqnbZ
         3mO1BP1moaQ/ljY8FIe4JTvHDfvLSh+uNagXEEpURbA40HZcO6D/Pd2oh/UJzy+uu9UY
         a9WXVW4KKZTdKVg2H/Ty3yTiCKn2SRY68z0QiFijVTZeafCW5aqjJJUXTnbbaod+qPjo
         7XvsdMQTNDi2F1HjO2Q52SOE89F4QWvJHWsx65KdwG9m7qdghMKDaK09H6S4hCFiz9/o
         Solj1w0RnMUe6DfdgjlLy9/x46ts71pEtqhNJyl9EbM7nBN0w9KFx3z5jqrtYlGEE4Pf
         2+ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706538110; x=1707142910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K4Rc7p9PWjQhQvhRCTBPdGfYJzp10T2+fdlK7XpBq9U=;
        b=F4Wc4TLzpuaBmHhyMV21s48q6dFe2V6vjCs9LOKDvjAdyIREdaqusGOKiV0gbmKgHh
         wkYawJS6nnhepC7Wzqm1XXKAZcSAx0lBlKdD/ePBFr5nUWmzZmqbOhd6w9JGazBKydZ8
         34ivbniKqB5KQYB1xsaBrJNxSsh0opRj+vOeDON+KLVRcHQY8L2lXTEufmZKK23hJwpn
         27FypxM47KWS8uO4bnVRno0nQO/k3BRdh2u7bp+OqNaLGjwbF7k42gTfVGK1WojofmQZ
         B2iSaUqYr5rIKzIuwou7XQ2xHa01QdHALwMebwsQioy9yC2CAnv4ydMl4sIq1Fk2+2NL
         z57w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz2UAN7tKxrhxcx6GPH0Rq4RZA/xXLNkjJ0GDoMSRWky2fY6mvd
	APdOzarnSjaYo/qiFeBMT7mn/tSOwDbT20CPTouNmTjcGKglxCHQ
X-Google-Smtp-Source: AGHT+IEVA75jFYryHExzvfTBPPvMXGZ1zBLv13/gDGzgPVWUsqC59VgV+Niw28P6Em0jZNi+gJw+pw==
X-Received: by 2002:a17:90a:f2d1:b0:293:f46e:a354 with SMTP id gt17-20020a17090af2d100b00293f46ea354mr1964056pjb.3.1706538109655;
        Mon, 29 Jan 2024 06:21:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb8d:b0:290:5f5f:57d6 with SMTP id
 a13-20020a17090acb8d00b002905f5f57d6ls973186pju.2.-pod-prod-07-us; Mon, 29
 Jan 2024 06:21:47 -0800 (PST)
X-Received: by 2002:a17:90a:db96:b0:290:3e62:92ab with SMTP id h22-20020a17090adb9600b002903e6292abmr1986740pjv.29.1706538107554;
        Mon, 29 Jan 2024 06:21:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706538107; cv=none;
        d=google.com; s=arc-20160816;
        b=P4fI5KnzLp/faUbfvXutGCZ3h9z3+j6GrT0OmVByPlHLZNXU3ag0ofGN/u+6ZDZzzm
         SzIhoK7GB9DvP4dUBwgUvkZFzyQRcZQfaLgS5zhgQ3Aw1mb99l9AhSai7hvoiZInRHTa
         4GnHBKPXYxzNDAI7GQDz8ppGZ2+s4coflBAkUz4fOoRCzzxpdQPp8fxEDC8S6bNHr/CT
         A7f6BAqXjVgsS3mC55lDQNSjEHz0Ga61731a4mW02SuVQrpQUUomx4t8F5Ytl4q5trk4
         aQBQz0On9PFOmr6qk8MnnvZleKheVYye4urZTB+s+euyx1NbLIFJtXhrk7iwWtIGA85/
         bJaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=kNrvsSmpv+x8uoY6x9zfWZ3t+6NvdQjMfcuhTt6uAMA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=WtkxHM7ezL20xxopLZ82kI6gbcMpzdaZ+sohgNvCZ8j0A7AQXbCGBrQzmjIO7dA58v
         IcaSxWPwucSFbUMK2rv6mPq6X0uw0KhwWpWWv1NTgrNrYHnhx7BaGmXghliPaHN83NHw
         /k/AWCVnEWt69dvns7VTiN3XEi5kThi4cBeXafAzL2hnyhtUoc+4XjDpVSB/BpXw7wKV
         nWGv6xF9XBzJgbzi2Z3jfX8QGIR8RlBzRHuho2jaFBgyYmPAny90irF0DSxCZKnEUzpj
         dNOfArcc0yzh73akZfFZR5drVzRorE+IhdntvHKWMIRVrK+X6oFCF3F8tVfF/M1dtQt7
         6izA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uVrT1WTF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id q22-20020a17090a431600b002936e2f5d85si565766pjg.1.2024.01.29.06.21.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jan 2024 06:21:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id A11F2CE125A
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 14:21:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id DCFB1C43399
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 14:21:44 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C730BC53BD2; Mon, 29 Jan 2024 14:21:44 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] KASAN: add atomic tests
Date: Mon, 29 Jan 2024 14:21:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-214055-199747-lH119G4umS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214055-199747@https.bugzilla.kernel.org/>
References: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uVrT1WTF;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214055

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #3 from Marco Elver (melver@kernel.org) ---
> [PATCH RFC] kasan: add atomic tests

Looks pretty good. Some comments:

- It's unclear this test will work for tag-based KASAN (CONFIG_KASAN_SW_TAGS
and CONFIG_KASAN_HW_TAGS, i.e. Arm TBI or MTE based KASAN). If you can't verify
that (e.g. by building an arm64 KASAN_SW_TAGS kernel and booting it in qemu),
add the KASAN_TEST_NEEDS_CONFIG_ON(...) like in the kasan_bitops_generic()
test. In that case, you also might want to rename the test to
kasan_atomics_generic(), since it only works in KASAN generic mode (and is
untested for tags modes).

- I think there's no need to say in code comments it's based on
kasan_bitops_generic(). Instead maybe just move it closer to that test (perhaps
right under the last bitops test), so that the file remains (relatively)
organized.

Thanks,
-- Marco

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214055-199747-lH119G4umS%40https.bugzilla.kernel.org/.
