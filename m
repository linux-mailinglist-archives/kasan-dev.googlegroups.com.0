Return-Path: <kasan-dev+bncBC24VNFHTMIBB6N6V7TQKGQEROOSWIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-it1-x140.google.com (mail-it1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CCB832B5E6
	for <lists+kasan-dev@lfdr.de>; Mon, 27 May 2019 15:00:42 +0200 (CEST)
Received: by mail-it1-x140.google.com with SMTP id l193sf15794345ita.8
        for <lists+kasan-dev@lfdr.de>; Mon, 27 May 2019 06:00:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558962041; cv=pass;
        d=google.com; s=arc-20160816;
        b=epGNcHJ5cZt59R9vO/znhxgzMbSPQ7dwLmKX5Gtnv8MiB8b2bHbpJfiAp3dKkZy3x9
         Yhz8K7riQ0pkZDs3mqYrYFL+xOxtJTPjYPh95xXKgdN6X93hQtXfOnyfL6AF0R9zrI5G
         uqXwpl9Ptvvn4miT/vB9/U7W7U4aBnTp6/lpdE3FbQOOo2lHIrH/DeIZogrd8Tq4Padl
         6cz1sVGqDGDmOLWEMZMHhxDed6HGvMExn1sxhd5A8iQgRF2sfyUUCNT7aIQusxzqKESq
         ujFqefUIA8+M01ZTKgQ/xKOlyB4c3inyRaiy04EuURURKX1io6eI8XPg/YPJ/H6/kQ2m
         9Dig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=PPHCsBxU8JU/s4vf3s3ALdAjhdHTAxT3LQUW2QFXb7c=;
        b=UMb8YBd0JuYcPmpwxktku3V/VDM32qpdTdygQoHNwvs5GyF7MqckQz69uU+CvpxY6e
         f69qJ8hJmdKaHn7ZXUcqzSde0sxuNZOZyb/6m7hXGsur1PLo2k8wiBjpShhhePJxtZ7T
         B6Gg4rPCOLXu2s6dzjkACBsOJ+cuQXh/Qm9BVLysq6rEKAWs5X/X2DzRpGBO6zll47Jw
         0bOhKPu58P3pocIHi3DGHIZNxDR0MDOideOXSQL8KlnM8iPgKy/8AQfHrl0jEJOhekqE
         9sphvKrbJjtuqmEtaogExoBEoy6rKUZKoQqQgEIaqScQPC4K9vO0J33OAWIL8upVPHZY
         U6GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PPHCsBxU8JU/s4vf3s3ALdAjhdHTAxT3LQUW2QFXb7c=;
        b=E4F+FGk10o7WOgYZG8vpR1geP6FkjScM43jqfBupOSzcUTvv+BRvQXrVRShire/sRW
         fxwv66a1lG/VtZrFk5EcJjy1lz3b1l9Cl4qyn3H2HXLCmlgetFhC6nZhmHPpzAtpa4gO
         qqYGnGwBXfcQ81gk9KnxcyebS2OwcPJLpOwfBN/Qh2tvYsK19GqJmyeZw6NK6vwdrwXT
         YEuZ7LENDtiaxNRjnRPTWEEQC+2rQ0ikd8B69nQnx8eh1l4bWIueoboP4+SYzXhwIEIe
         e3HjcNMozxfb0b4CkGU+tAwHJEtSZF/I5wLdF8L6gmfnB3/AaRjb9vAQyZ9RxF3EY1Nr
         HHLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PPHCsBxU8JU/s4vf3s3ALdAjhdHTAxT3LQUW2QFXb7c=;
        b=NOa/x5kPQ0HlQVGA184oevAGPz4S/TkvarUrELkhBjtMALErEeXndKhns+cbx2PkYV
         RM/Xd9GNGXbHmDjM+rPagNblqsof8CUffUqMLP2IVGL6ypftKJglMSdFxwTKhPR4t6dE
         PFbLb7YDTRh/tnjhURCwf/rE9jMORv5Ecss7iovmtIzTcba7Wtw5LgN6Mj+ZK/Ic0Gq8
         wvy7bukCpQInkcpRN2ApTe9C0DoNCXgXVYAOy8emJZfoa5FWQRaNBxPUKoBPpO7jBT2e
         f4xGbD2C/upEV/whwCSSmdkJ9mwQv6QhR/nZzM0LmyuwgGEAYto50Iflfdl0P8loufo8
         EEhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUeybz7wg1z+JMlHtePDe9tMZ2nPoRhI2zL8OuWtsOMQ7pCGJrC
	HVw8icQSjwwXrcUyAsNwxFs=
X-Google-Smtp-Source: APXvYqxlg+zbYEIJM43o3qXCh5hlbjLYNVAA8Ps1BmE0lyXWmAHNtxRiOTaBS/yn7WgwUtLRfoA2jg==
X-Received: by 2002:a5d:8712:: with SMTP id u18mr12819642iom.18.1558962041426;
        Mon, 27 May 2019 06:00:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:6295:: with SMTP id d143ls5012175itc.5.gmail; Mon, 27
 May 2019 06:00:41 -0700 (PDT)
X-Received: by 2002:a24:1d8f:: with SMTP id 137mr28391660itj.66.1558962041139;
        Mon, 27 May 2019 06:00:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558962041; cv=none;
        d=google.com; s=arc-20160816;
        b=YqUgq48CnLI6vL2N9qQERNcuGQ7IJ3cnxsHRPw4aaVXLM6BK5wtv2YK0vwdembpzyf
         1sL1oXutd3pElUFSYcDP5cMOf1Xwh/jRVPZ+9vv1WqOU8yF+oAqB1Am2NGjM52jVY3Aa
         5NLMlVIhHQglw5lGFzcEhRNwHsG/r52duvwG1Iy0V/Y5iUZ246wqyVlg6U3qeqKyzUZ7
         GvOmJjUMI8IBjC4Uvx4mAT1LvX0AJr3RzRy5mEOkhRGI8Ha9QD4YqWDna29U2nx00RLa
         rnjXnLAgINrjPai1fECBdsVUg39622ZYrnjpq6LqgqxKp/wZ3mTgnvIC5DZCpYoetJK2
         xxgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=xXoqeiZL8ohjsPsYZz7kQx+1BWI5tiuveVVA62p7MJk=;
        b=TlWIPVLxxWpjbVqDyTKTwm+pdE1thfYSrIahy3BSHB9zQeDxbFjbrmiB+IdvA4a9XE
         q3aMsLEYOCFo/5msjt7V6HAGMW2d+9jx8ApQa/vXOJcrAj/rQBK1JcFIU/lb0OFFxcYT
         EqzYx7DCZfmPJE0jxID2eL2RpM4n8VQV1cR41YT4ij7RlM9CVl/JbZkxjAdcVSqAAS+y
         fxN4vAJnU07VZzrH26wXzpdzvn7yF2zS1JVhFtr/16dKUku0Cm+M5kSUZemBgSRdtBQZ
         xRJRMiMdAF8kdYBKPsqeqat7DgAiUoNHdYX+Yp6mI6QZPFKm4GxhJopg8HYK8ZkF+DHG
         VVOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id z2si386199iod.5.2019.05.27.06.00.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 May 2019 06:00:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 55A2D28B44
	for <kasan-dev@googlegroups.com>; Mon, 27 May 2019 13:00:40 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 4570A28B60; Mon, 27 May 2019 13:00:40 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198435] KASAN: print frame description for stack bugs
Date: Mon, 27 May 2019 13:00:39 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198435-199747-tdFZvgleu9@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198435-199747@https.bugzilla.kernel.org/>
References: <bug-198435-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198435

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #1 from Marco Elver (elver@google.com) ---
Patch implementing this has been added to mm-tree:
https://lkml.org/lkml/2019/5/22/224

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198435-199747-tdFZvgleu9%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
