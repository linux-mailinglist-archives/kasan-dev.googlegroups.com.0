Return-Path: <kasan-dev+bncBC24VNFHTMIBBQPZTWBAMGQEGGFZGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F208332790
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:48:50 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id h12sf10204140qvm.9
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:48:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297729; cv=pass;
        d=google.com; s=arc-20160816;
        b=oN5BEVBazJVYzSm/2VAHeft5lzjOQm3kPksrfQh3KlF4uW+ThSvuF0zzpcT5fbMTD5
         oShpa1aWT/YsX1He9eb+ZH6uFZxDlY6Dv3Sa69N0+IlO+AhvDu40abKCBTslR3R5GmGG
         25mWB1jFKSU9pO0pRx1vbulgVputUYAnbSOrNDK9+uZ8HuytkSevp+9pb+sl0EtXkvoJ
         MIxd7lFAxeLSX9RREjuTBowRvdqc6emCnAIyQQpcnwpRW3zqCZxZSm5wErTO9j5OPwex
         ddb+mSMlpJz8fbZPGeaKTun1Ceb35Uxi9MX6M9G5xmaRbHTilLnQHW5Estyz/UNa6+jD
         epiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=EbW8fuA63F8DwZwFY6YqMJbRgxO/6DcvQYGKZX9J9bI=;
        b=fIh0lqBIN1xCwXnyuKQHgEvMzspn2umq3N6WqOLUseG9ZVIte5Eel9KzC6lLmImDIn
         7JF74SjOTZtdD95jNjYbHvazb4s7wtKn6e4alK9i/RBzUURPlGgni2d/yOOgC54S3YM4
         2GZo6GTV7vylMBRm43+HuDulGSSdrLJUPILcnVkHLgeBL10lbHD0uohmeMryY2ubCFfx
         8XtGLZ++VhzJ5kIr/njAoY6MMvggdDrmU3LYWHNpDz1c1qnCr3JHyy+T6wVyHXetBbww
         spR+DO1VT4QRZFC5FdMuUi0i/6Jswf9nuF2r1RMnxgBYih3L8T9mricDRKSVkDy2HY5n
         SNEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="t/rpfhn+";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EbW8fuA63F8DwZwFY6YqMJbRgxO/6DcvQYGKZX9J9bI=;
        b=gjWiozlN9u3f1VsAvZXVKvuLsN0M0bw8YRrDCjmiCWlIE95R6hSvL4d2nlFoPOh8Rs
         LsLtVr7BfqMSFV2wxucR8fnEvqyypIkxGVYK6Ofaf4PoONxEObAOUKJQfRIG5xQNmp1Z
         rCx89mivRlCBHB79sMHwYhHBR2VDBz0aDqp+xTNgvzyTtQzsBuz/I7WgtU5DP1BxKCuJ
         jNnS9dKKwXSjjB50biJ2Oim8IQjcscvcze8/5EJzoNuEFZm+FHIW85cbtHcTFk7yYuFD
         f7cPGie8upMjiWOoB1QtHH+j8zZmzp2EjddQEHL0YOg4hMhB9cyH7IJGmAC1pf8+9J+w
         ZS+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EbW8fuA63F8DwZwFY6YqMJbRgxO/6DcvQYGKZX9J9bI=;
        b=C7n91EmPSLYNS/FDJZRyhPH3p59zMAZY4SrOtVwh/ldrNTeNhPqeW0fDUAS01pH4rU
         Qv8iH6lsy1TrtguuvmQL+UZYwGtnwdeRhF2qnAYbydK096MJ4CUGbN+ssspyfwItgtsx
         vMQ2YgaKRPiojwRSW1SDJ+Mh0aKvRhUWfb+P28pVOvnqplEJu6SsdlYsONbITXTfQh8k
         R4p9C2zbfxRcgXO99R9S7/MaHPU/3RbVTXJ0VZVP+opsFxLxk3c/zM+TXMf4F3v6PKSp
         PrfDHi/Gc0u/IZupI1X2M03UbkT9ID8reYmXFxojlefkuV0+nZCgyxw3yRf7YPynxNQ4
         yNxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hj6y4k6uhGnW0h/+poHDrj2nb4ndnFiTpWuxrgHBtyYb9V6fZ
	7/2Vu/Zsimz3UFA2Vtx/kVs=
X-Google-Smtp-Source: ABdhPJwOlGETOfLJdGd6+qbTgcJvo9AbxQdbp+EkZtBVGy+dh3K79T0zlBRk8worsC8kCOz8gy441Q==
X-Received: by 2002:a05:6214:268c:: with SMTP id gm12mr25070525qvb.36.1615297729190;
        Tue, 09 Mar 2021 05:48:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7497:: with SMTP id v23ls7209980qtq.5.gmail; Tue, 09 Mar
 2021 05:48:48 -0800 (PST)
X-Received: by 2002:a05:622a:14f:: with SMTP id v15mr25712707qtw.212.1615297728756;
        Tue, 09 Mar 2021 05:48:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297728; cv=none;
        d=google.com; s=arc-20160816;
        b=xt2jzq6i/hKKD6I08itXq7eZdAyUyTf54gSLf5IUisHxzRytlojVqI+xgab1/w2iDZ
         20slFbWPUzEIUPalOrLglspOxWlfvnAI1AABhppj2DDYFAL0fAsAyqBMuiuFb5RacoVx
         +M98S9ZNqXEzAGEc2n0/+GbSWHBYOjaOZLkNBWkNsUIrIpP7U6/Gd7snvk1RwJru5AjR
         6/7icaXmIeHfu3NZSG4NZFZmSIM39LUr8ukbpTN70AUvwZ3wELw2syqiBBfmjD1HY5Ck
         zXPVH0fqFRT3kNY+pgVtyT9xIiC54mzK+LV/Rbfj8kxZRHn0VD/uuhYDA6ul2KaeblCP
         biWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=29Ec+CEU3ooaGL5mSex6ceXs2LKVPJ9M8+PHNcrUxao=;
        b=UKKlS+7LYmyDZZpgSvnxKYjYk9KeHRtlf7vIPjqldbcw4mbRB5PK5rTIjdus5/9Iyr
         60TsZR3mTeyh+CPcrjQsUJFdOBl6D6NbYtM2DXnTHaNfZzhZVwqiJu4302bBTZzdrZdQ
         /cznPbMbDgthQ5pajRFVIpEzI5gjGAfPJPlCtyE40AX8IbqSgGKpTCwHl5OeOg32OckQ
         iskWSYesUkF75lxp58huQ9QpmpnSa3Y7ylw85dnTo4AOLy11ktRCHlf4dTdyt3qAe2iJ
         +A4xYnOiPISwT6tV6RIqhM0tqQGPOqbTaHqNUmcrvlGzOnk8/+FGPHEs6CiSlUqUyRip
         3pyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="t/rpfhn+";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r24si642985qtp.1.2021.03.09.05.48.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:48:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 88DC2650BB
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:48:47 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 7879F652DC; Tue,  9 Mar 2021 13:48:47 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212167] KASAN: don't proceed with invalid page_alloc frees
Date: Tue, 09 Mar 2021 13:48:47 +0000
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
Message-ID: <bug-212167-199747-9jPRZda7Yx@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212167-199747@https.bugzilla.kernel.org/>
References: <bug-212167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="t/rpfhn+";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212167

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
A part of this change would be checking that the memory is accessible in
kasan_free_pages(), which might be useful on its own.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212167-199747-9jPRZda7Yx%40https.bugzilla.kernel.org/.
