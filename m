Return-Path: <kasan-dev+bncBC24VNFHTMIBB5EEUOBAMGQETAA5ASQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 41BC7333D24
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 13:58:30 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id k26sf8633044oou.15
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 04:58:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615381109; cv=pass;
        d=google.com; s=arc-20160816;
        b=U3J7jfqpG/88/msX9+Vq+3/OMw6G/NnaKvJioi7XM10Ok1gj6Ef/PHvX3lr27zX07I
         xzq86eIY7AhFalvy4HeceZ9hpZxt5Mht38VVP5ICL1GSXTXZUZlg7NsvgZWyo8ysXV3b
         p93Bm+4dtt+Xpyux6q/XaX9pbFIBc4zEoX9+jSOCvf6hbU8r4fOmDVDX421cl8IIbSNt
         CmqyYAUl6GbSDaVJqdmjC+25KxIDXKWzXmj0de98W8xK2lzEoL1G06Bu0kfyvusa4oTP
         eh52rrHpXa/iRQgFICtNMU4lqwKieUbnlW0TpxYZfAy2Me0zACwQAsgAbz7ECJQmt5C/
         3jkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vza5xTjuggulWFHXASgS6RuL3LRFPND6s842jfIxvss=;
        b=pT5I0PMXACH/NvS8zmPZ+WDWnNk2qQZpv1RW5qa2d+gcWSRWZiwLFar5ty2NUF4tig
         fdE2ULiYK1VipbSXz/tyh4q8nVBmO4IgnSmnHoU7Qb6O2VqkUiLdjDc+H+FIWoNmlfDI
         FsJOenTjpLrpBY+UG9J8HaXxd35ZvkgIwuINJZsnP647Y7uKjSUaf4vNKWwrEV6qJkIv
         NwjEQe5aBaedPU6oeSHv5u8R9lhsdU7NrNgJyOaJ7e5xStkrfpH11El/gyI9CaDbe9ns
         1j4iokoaWobURRmluK9jjsQ1sycCHjTtlNZko2fZflQi3q0jAAH9RNaxzDaw6d91NxcA
         aN3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dfrg8Rjk;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vza5xTjuggulWFHXASgS6RuL3LRFPND6s842jfIxvss=;
        b=DsJO0LAMMG6M+5ixzpwNWRRNg3h6Qpb5agWmZl3NnQVQPgU0zFygXEDL23M9ZvL3UL
         ZopApnd39iLzKt5qUWlV7IAHf0siBqpwYI/8h8/2fnxCPG9570z7Aul7TGpeu9pwyhPQ
         Vm7tNownIK2T0WvU750xyLYs17J2XZvFq3ssHPb2hj5Hz9SGQFEbK1UDsYALKDZjz1j7
         UpRqPS/LbtClO1xI46jINRu14keWJTKUfMLOLO76/Ji7Hl0/ojcbXnBM3jkRHq5+bEin
         TJ87cZwiA0Qme75Z8548EW3DE/CXDssscUwfmdAcHBW8rcN2ftD2BQlQsVHVHoBPT9e3
         STbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vza5xTjuggulWFHXASgS6RuL3LRFPND6s842jfIxvss=;
        b=EcfQ5oPICGQt/9FAk1Oy6+os7NoxXTZ8UjTTYikBpxg34aitIM732FnKcukfCGNZ12
         jG3xGd0S/cnhI4tHMGF+tLXz5OpWxlV4MYPfSWUnIudF6THy86lUlMOg5iVAfnlX7Um6
         6GZGKUvMbPiuD9YPyKb/PIWtEbtLUZpK5GoXbA9a0MIun3ZVHHuq9ldVzF4nopcCJii4
         tK7Q+fK+cE5qaUFtPHKY3E9V1W36brhKY3CgJ40sWa/7r10kG81fnC15OeoHwvEQ5DyP
         Tp15JnHuZGwZBe+114wbGEwSXL9iRMNioBttj8Li0ZC8q+sQwY3tq6+WfRSEa1xxTVXh
         fiYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XSuRTnsqvfDgsDO7cN6GxCRGTFbVHmgPC47lhQbimBzDrzTfS
	7MTxeJNNykle036cWY1mYWc=
X-Google-Smtp-Source: ABdhPJwWQXwGqm2Ncp8Uqpgxb3sBtTthEXcCqRCKPiHepfYj+FBfFKVHulkCclSwU6yZcBD7YV3Xzw==
X-Received: by 2002:aca:5e85:: with SMTP id s127mr2164291oib.67.1615381109007;
        Wed, 10 Mar 2021 04:58:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:65cf:: with SMTP id z15ls523620oth.10.gmail; Wed, 10 Mar
 2021 04:58:28 -0800 (PST)
X-Received: by 2002:a9d:3c8:: with SMTP id f66mr2366090otf.246.1615381108657;
        Wed, 10 Mar 2021 04:58:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615381108; cv=none;
        d=google.com; s=arc-20160816;
        b=OTCIDHov5/I7cCW+wHpfRR53f9kCMW7wk3rymcThi/qxxY38U/fwMeQedDQJKJieHG
         EZO2xkl5Bsa3CZM2RcIbB/qqOysC9shmA4TBS/2vjJxZ8XPE5DHIYcDbjw8KCqxvDsA+
         nKhtUZyhZOlRyTTQ8cW97ZQAv7q0RH8J1nGGqJ6bFQe0z+J17voQpyEthWzBsvvLWvpd
         RTZGvnJvTwmruzTPYgm8IS47+W+DHtdLfvFx3t8JIxjYfkIv8hugFcIKO4lgGgvSyght
         P74JkLyi5pByY+1ZBTCgTHB4/2zLc7jNdJGwTHQhtviGf6+EKUfwHunwXsCp6lsfv2e2
         6PZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CuDmGE1iOy3tc4cQ6HtRgi28NdOHB2w2HF/n7pL+2YU=;
        b=o5Osx9oGqAWfaT5c5VGBlczEl7qRhG9ypegZY5pS1TiRao0J3BIduatj+5AQsn2NSD
         BG48CPMz7sNH7nqsMvC090mHpfzIVC/mYZmDzJq1OkO/K4AYsotAxZ7RsBNZL3KxRDM3
         F7BwAAMlYWPJJCufvpPgI1g35AYRuF/OAbVOZv8xkEooTMCbLUIyKJoLKWRiW7bb8dyG
         J/acz7YYEe7a/efv17SeZtqAU9AT7Rm4OKfW313KtyOUZjxNLJWlmZmQ11+lSlFDcxhK
         mJ3w2SUJ7QNMS9AW8qpvi34IFu645FvpEDRh0tDmDOwPb+yoeySQ1WgboZdKUmISS3w9
         2wHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dfrg8Rjk;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d15si233923oti.2.2021.03.10.04.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Mar 2021 04:58:28 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id AF03B64FE7
	for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 12:58:27 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id ABCCF6537D; Wed, 10 Mar 2021 12:58:27 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Wed, 10 Mar 2021 12:58:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-198437-199747-Uppi5OsxAL@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dfrg8Rjk;       spf=pass
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
             Status|RESOLVED                    |REOPENED
         Resolution|CODE_FIX                    |---

--- Comment #10 from Dmitry Vyukov (dvyukov@google.com) ---
I think it also makes sense to memorize task_work_add() stacks as aux stacks
otherwise there UAF reports like this:

Freed by task 93:
 kasan_save_stack+0x1b/0x40 mm/kasan/common.c:38
 kasan_set_track+0x1c/0x30 mm/kasan/common.c:46
 kasan_set_free_info+0x20/0x30 mm/kasan/generic.c:357
 ____kasan_slab_free mm/kasan/common.c:360 [inline]
 ____kasan_slab_free mm/kasan/common.c:325 [inline]
 __kasan_slab_free+0xf5/0x130 mm/kasan/common.c:367
 kasan_slab_free include/linux/kasan.h:199 [inline]
 slab_free_hook mm/slub.c:1562 [inline]
 slab_free_freelist_hook+0x92/0x210 mm/slub.c:1600
 slab_free mm/slub.c:3161 [inline]
 kmem_cache_free+0x8a/0x740 mm/slub.c:3177
 rcu_do_batch kernel/rcu/tree.c:2559 [inline]
 rcu_core+0x74a/0x12f0 kernel/rcu/tree.c:2794
 __do_softirq+0x29b/0x9f6 kernel/softirq.c:345

Last potentially related work creation:
 kasan_save_stack+0x1b/0x40 mm/kasan/common.c:38
 kasan_record_aux_stack+0xe5/0x110 mm/kasan/generic.c:345
 __call_rcu kernel/rcu/tree.c:3039 [inline]
 call_rcu+0xb1/0x740 kernel/rcu/tree.c:3114
 task_work_run+0xdd/0x1a0 kernel/task_work.c:140
 tracehook_notify_resume include/linux/tracehook.h:189 [inline]
 exit_to_user_mode_loop kernel/entry/common.c:174 [inline]
 exit_to_user_mode_prepare+0x249/0x250 kernel/entry/common.c:208
 __syscall_exit_to_user_mode_work kernel/entry/common.c:290 [inline]
 syscall_exit_to_user_mode+0x19/0x50 kernel/entry/common.c:301
 entry_SYSCALL_64_after_hwframe+0x44/0xae

This communicates almost nothing.
And there is a number of these:

https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run

task_work_add() is called in few places:

https://elixir.bootlin.com/linux/v5.12-rc2/C/ident/task_work_add

so it should not produce lots of aux stacks, but most notably the file closing
stack seems to be critical to understand lots of reports.

Walter, what do you think? Do you mind sending such patch?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-Uppi5OsxAL%40https.bugzilla.kernel.org/.
