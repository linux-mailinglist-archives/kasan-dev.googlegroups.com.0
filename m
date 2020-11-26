Return-Path: <kasan-dev+bncBC24VNFHTMIBBN6B776QKGQE3KGSTJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D5B12C5A13
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 18:07:04 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id v3sf961929vkn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 09:07:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606410423; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1Pp7IALb8IZJKou8MFf19+I8h0YDnZW5LN2+lAxJB99wzX1kHmrJVJ1tRRcRJdzlP
         bsHLyV3jqJAX9ixNSjipLnbeWPMkjxkTuDBEpXwa1736PER5mGniCTmXjfcthjisgbkS
         gCyOBRgpea1vQg8EoRIq3hDrD+OBpfZjy5n+0HFfAHFZ4wJKVLPoM8AmEl+UoVhNDqBr
         9qGpDG+P5SKMPPLzlG7WmwhIKwy5wt5ItXZWU64n8BDqJA1b3gljqPaI/RzWD0vsEQIz
         G5/+QPHlT5L37901YvzeUm56lh1ZSQxY863AViIRPYcQ1BXOZH0Ex0k+BCGbvwQii4rw
         nIgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MlhyOy79G5kG1h/2jsd2NGpRI1EG66RZUDd+591fH/Q=;
        b=PQUabhw4mTs0o8ZvvVATZMvaJCeJldQR8Q+umqkyBqEEfnvxMce5duVB0dWtDj11oS
         YQ354YSAwVZPJIMkjDdjIZDjeahI5R8N+RSez8LlYBk4lI8YY7U2/qmTtF5ORx5UEpXp
         5g84ukx+lV0C73LjhwLR7P/lc6nB23lwBEMxMUr30iXx+oGqCoIuWWSSDA36AxUQge1D
         cAKD0GrdafHbgWt79gNTg/ahaKISCSXKcxTzfL9Kif7uw07c5IrZhOPF21h69HIDcxij
         cC/8wfGSWDjPm8SnbgH5ZCHCYGyTGgSK2j09xG29s0xz1Sz7ylF5ueLqjAYAlPIjMt/6
         Iifw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MlhyOy79G5kG1h/2jsd2NGpRI1EG66RZUDd+591fH/Q=;
        b=JkX24g8GJKnyzf8whZFyZxj47T/EjJ6kPimQ5Sj+NFZWFhdbUFuZ/iAteSbiMUB5JE
         FQVNdQW5yG2lyNWBSyQ4Xns0QrjwYfwmVgNKyGPwzuz3+52ZpyV3I162ZOWKcMgdPf6K
         VYU18RNju+rqeqJKGN6VITYwo72Ca5VYJfAy4E2LTc02BctarlFZwu9V8Te9MVhxdomA
         2WTOS7fGe+bqP4/BW+EqE+Ufv7pE1tE/ItWsZRumPlL1HWkjsQddcMttYZpTgllrMz3a
         Ct5LbvEPM7r+74MzC1TyC0fLprWK5zVbBlE0IsFfKLp8lOPHDlKl5SQYCB/9JZrlido0
         yTnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MlhyOy79G5kG1h/2jsd2NGpRI1EG66RZUDd+591fH/Q=;
        b=XKVXNf0ZSloQzC7ooFOfpxPuFiGavMNJ0OPUVQMmJiEvHOROlwXP+CVDPzbGU1rmwn
         +4NtcFD/o4MAWjZzxJBXYV/QUWdi+m27RQLqQ/kn4Akyc4p0OhDLPB2WRdEw5Qx3mlAJ
         mZkIPstX8vop60YMN/VeVV9tCEstSJhRCzibuPLK4u8PxPjz+3ZITPoAuGl43wf9Pttp
         Uzxj9az8ZHqaA3SxJYaFtvE/mJPoNOVWohlFXocD/dJu+hJ8552pSuKeeihAtrmkI7Ro
         rTwRkXyRN/b5yEOlEwcVAKLmL4tQjW00TuFACio8pAamN3VYNv5ZDe4C7unE6KkoKJrF
         oMFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ju5MPhV37MAFn2Mnm+PBY7JW8qiezIzLBeq4s01Hp3fBLk4dQ
	EpL3vfDz8Iy+3DvreLrheOE=
X-Google-Smtp-Source: ABdhPJziVNC3G9O+amrXMn+eW0tXa+hohGtJWRC0JiCZ+L5Ghn7DXBSzBy567J9cXARWVl7lNSXzJQ==
X-Received: by 2002:a67:f646:: with SMTP id u6mr2533434vso.5.1606410423382;
        Thu, 26 Nov 2020 09:07:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ea12:: with SMTP id g18ls306914vso.9.gmail; Thu, 26 Nov
 2020 09:07:03 -0800 (PST)
X-Received: by 2002:a05:6102:312d:: with SMTP id f13mr2577639vsh.47.1606410422980;
        Thu, 26 Nov 2020 09:07:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606410422; cv=none;
        d=google.com; s=arc-20160816;
        b=cW5v8lNrAV5qp/4FwH6O/GIhdCCamLRrjbOBUe+mCttRJo2IgVxxZ+s+hIhuUWV8Ss
         rr9HXU3gPfO6Wc+6dzKHRfiUpSa5um/AfI70OdiVylP7VjXNM+agjbqMzECoMVz5aRck
         pXhmTnCose4QsoqdgJFPhVHYxitZ5YanMVt2TOWED7b2ELsfxrQWHDkE1RRDZVe2JjTf
         rlzatj66vuqVX8ZrN9VnB/N6D2hWc3rpGfpZrVaW8AU06JLHykVLwkSooE7GsmRO0ayL
         YymRKbEqF7my9z6yvxHQDFPi9a26bPKA4v+Rm/x/9GTon8zf1u8TK5lHWE9ixWiX/h1A
         QnXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=RzIsJJTWqQJOWjzasooTu8tMYFRz3aD8iiC8erf8cLk=;
        b=B77o+qYeckly+Kus+ms0mK6lRr5y47MRsrsSgxysHspjbqC2LWygk830zvhXiEC1zl
         OWk1815u6RhfTx/KRsHAs4jUXLGpbYXy4R01XpbWtNNz/gJOn0SO8FLGWHI2qmgWlST8
         sk30lwUP8lpHvyx92CV/qRJ1vjD9n5YBTYbU9/Rt3Les/+b5G0RUGte/WzVqyiPYLWu8
         7whLjSsydsag+SRjy3MW7oDlISOtDop/Vn5L60X9r6YaTxSxhgm3wcwVZVec7p1bNgs/
         WtOvYmdm3Jtb/eUybXtv4vgM5y1vbBB/aHVrRIBTf6tjbYPZSAIsdsEC87Z4n25B6dfC
         E1gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s9si112571vkm.2.2020.11.26.09.07.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Nov 2020 09:07:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Thu, 26 Nov 2020 17:07:01 +0000
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
X-Bugzilla-Changed-Fields: attachments.isobsolete attachments.created
Message-ID: <bug-210293-199747-i5GZ5t8WUK@https.bugzilla.kernel.org/>
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

vtolkm@googlemail.com changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
 Attachment #293813|0                           |1
        is obsolete|                            |

--- Comment #14 from vtolkm@googlemail.com ---
Created attachment 293827
  --> https://bugzilla.kernel.org/attachment.cgi?id=293827&action=edit
accumulated leaks with line numbers

 as previously suggested/requested the corresponding line numbers, hopes that
helps to figure out what it causing those leaks

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-i5GZ5t8WUK%40https.bugzilla.kernel.org/.
