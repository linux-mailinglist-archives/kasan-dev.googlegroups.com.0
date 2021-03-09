Return-Path: <kasan-dev+bncBC24VNFHTMIBBEFYT2BAMGQE3DINJDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD53332B5D
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:02:25 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id h21sf296200oib.4
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:02:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615305745; cv=pass;
        d=google.com; s=arc-20160816;
        b=MYAJdml1fWDUtk/vK49bkks+tPWBTfUVCDLxQ00mPOpW/aevlPQNFdLUXGfyRIFK9y
         VTprftK4LhP+CQUzeEDsbzf7QH6wWnzOVyMe54bBIg6hdyeK/KpqYlhqZRPYhen/HLYG
         zz6Z5FuIgJYxfQdUxI4f49ERVNs6dlH2jHyfgVank6/rsMddfjawMx1HUJgAuz9n+89Q
         fW5+cnl5y7VwG5tC7VMG1DXeKVdMtOSvK8cli62f3IPXbGOXC2ThrqnA9uVZUPIgIjgJ
         TEmUp0tm7GpcDKW/CAoTW+b6lj4lIua3667ES5+GgK4a93KplRNWXrOxiNIH5obJj+s0
         ruDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=KSJIDXDSdGC7iyyc+hkQGbp0aw9gCPvAhOiGhXSDxUE=;
        b=qASyXQVa/Z8c+3nqNT9cT5QtAhbKj350suWcQ+lL6UK/+kQHB3GBjcBK+D8zC2ZfXx
         jPoSgBYINp5U7PG0iTEsE3nG2PXGIvjFclKBp0x6GnYhHWLKxn+SfdQBpqCBD5QEOknh
         YidkWvLm918hHMow7HPSvQXc3AyPgetIqjDFE2qK94NKSEfR8K84Z+vGafjHoJOo+Lzc
         ADKujW7ssJmTha0FvmIWhEumUCtwI6udrWb6UP7MRzIsYGhx0MQX4aDhYOFNHwNG6G6v
         56u4UlfJE2hIeiCtkFiAHyoOfikSiHgYKpgzkDE3vvRV3ZIDtF0Guc8/v0tU3xR3paGX
         60tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e6udYyCQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KSJIDXDSdGC7iyyc+hkQGbp0aw9gCPvAhOiGhXSDxUE=;
        b=Y2OAa4G03jHgBEMg73TuTE+9TM58lA+9nIdUZBY1bdNyTK5X97CXjqh48rgo+4zLwo
         pt+ewoFciOn88Metj4lcC9uEIdB78C14NzO27WJam8HltILZammnxuT2Wv55Yrq378GD
         YiMo4LoMnSJeRJKSYCdqD/LhSgTpCFLzccLXsh622wYwulH+czeFP4ptF6zQirx4lDap
         WNvoQwhJA4TDH5UZufSmJWJwqkyMI1+p3M8qRXDr+bAhyvwZkY7fbYV7YSf2X/4fpazu
         xK7PKYf3mnm1EzI8VQWZ9obmjs1rxj9aj7XrMyE3/RRDPhjrI6VvFtKcsQTUzeSn0LLm
         s16A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KSJIDXDSdGC7iyyc+hkQGbp0aw9gCPvAhOiGhXSDxUE=;
        b=YvkSHn3Hr3+3jzbrOTP8MIlutOdSDz84hpgwaQrHCvZmRha2XWFWh3ybvxa4nhSYTg
         kkMSv58anLY5oQf+tU0/Waa1pKEmzMOhsr+bhHcFDXHg2QwHIJuB/a9voeX9Kv59S+7A
         aCYLhETK2mdNRnv9WCc9cZgBiRV1Q4o3tw7QlM6/MsDKZt4BvOaNaOpZhG1FBgByOKk9
         nZgUsGEk7fSa+Yy7XMxqChDR6fGeKg6mKhy1aoCbUZC30At7kpx75OqzUZ0gom4Cabm2
         2fohI6SV/DbJ2Jem8DWVlbkwXD4i1CYwC6npRO6Hfi4eSDpkrBXQKhauTWGjowy5Z628
         bVIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531oiF2ubbMG/sbEzXWTvhvynWoAofLpPhV8ZGdI1tedAfc01Sju
	E/4unR1vj9JtaC0wFWTNES4=
X-Google-Smtp-Source: ABdhPJzD48TleYKDX9ECdTIIU1waou1+6tkyDt0qSaASeu2hLP5rTqUBcExxMZm5r/JBg4AnG8n9IQ==
X-Received: by 2002:a05:6808:114e:: with SMTP id u14mr3545390oiu.156.1615305744874;
        Tue, 09 Mar 2021 08:02:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1156:: with SMTP id u22ls5424989oiu.6.gmail; Tue,
 09 Mar 2021 08:02:24 -0800 (PST)
X-Received: by 2002:aca:5c02:: with SMTP id q2mr3463536oib.24.1615305744563;
        Tue, 09 Mar 2021 08:02:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615305744; cv=none;
        d=google.com; s=arc-20160816;
        b=r98qFtfIXaFvi7gHEGIQUXafCoz982LplVmfut4m4SXnZEak4/vWZQ8Qlxqm6GxoYO
         BOciXChxefUivGS7WxMubYtDgpnHmqiFm0rUE4d63q9ymxNaba6heIu+9N40K2lsHQOy
         aSzV4sizvuETCumFUJd2tS40s+Sd4Q0oVwNFba+WEQtv1qyZMzJXXOh7PoQAvgNeWSCy
         GO82hdV4ig/Axg88y/UTshMn8ZedMy4PmUN6an2gu9BY5PwRexvERq926FFvpOq8kHse
         +6xBSE7B5PbNGmO2j9eGDYgIatHdeJSzlJgp3veIQtJuBZh0MJ236tKOqU3wYr5dqZAV
         TobQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=gqnIvegIVrUfOBydN0wIeQjEjqVq0iF8zFQi4abgwCQ=;
        b=jDj7ns3p/BJTlSjRoQfkug2cRVKCuB5CtOu2bQ8YcX91cBY1icdWSiDMwQgyHiuVjA
         +LWfPWnt43KxVmC9AvVkKqk7KpRRuh3JtsgHGPy/yZ8FdfakHOPl9CQDpuL+SIhwMOZw
         +BwEy5GBxIJwvXLU+8n5Q5+XAnBruvlVfF5j+0bHvKQYbkV2l3Nq15qbC7GPAkm1WAuw
         Gf67YiwjWxy0vjvFGq/eQoGL3UIpwxvolo9Er5HULd2FeURlI9mZjZdzfEhm4vJJPhP+
         qYN/hQSzugeHJ2OgnCDg5xz3KaMBYfIuopna4lVf7dfEQgjoTWJy3WTonqUOmnx6UK47
         WuaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e6udYyCQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v4si1379730oiv.4.2021.03.09.08.02.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:02:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 8A8AC6525F
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:02:23 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 857FB6536C; Tue,  9 Mar 2021 16:02:23 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Tue, 09 Mar 2021 16:02:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203967-199747-IkrZfGaQ7n@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203967-199747@https.bugzilla.kernel.org/>
References: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=e6udYyCQ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203967

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
CONFIG_PAGE_OWNER=y + page_owner=y supposedly should be saving alloc/free stack
traces for pages, but I only see dummy stack traces in KASAN test reports for
some reason.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747-IkrZfGaQ7n%40https.bugzilla.kernel.org/.
