Return-Path: <kasan-dev+bncBCMIZB7QWENRBLEXWXXAKGQEQWCAAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5385CFC66F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 13:42:22 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id h80sf3849630qke.15
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 04:42:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573735341; cv=pass;
        d=google.com; s=arc-20160816;
        b=JyKCSKndcc7hVQE1ZLNwd33CueDduKrFHjacMv/xzdvHWUcSlqitOX7h6nw27KyqSN
         5GfrqcxXe0NJf1jYih5w/7v3I41Jd0sSqHvK1pw9LgbLF7nWj7KCbsASKy7QNrrmNKfs
         OfCYqOYp/mgjR8ihrvSJjAml9r2366mxW2BEuKdclg4Wf7pwG148GxpLE3TdFPp0YyME
         KG5PZYIwfA4p3y0XL/iZW6PgJytKUlROMOwZhucngG6KMblRLE9odtco9YwdW+1SKM+n
         ZBB/hyke+0ulLnY5GOcP+Xs0cWUG4u6LnPwT11Uf0mNldBe24AOztWUNP8w2Y5WJM9XO
         M5Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O5j/aAsE+bbxyQPxcHwixZQu4Z5am3/AxfptMqefL7I=;
        b=D1/j7PLR5OFMLaptu4jBWvifL9fXRzcXb6N8vL3kbbdmSv5AJNLpoBnuynFZbzPb0N
         975XLRn2F5Mx8mmujkXzW7f0ngCoz+4Xstgb/uvDi/EA2Ycjv07wS/+vOXLuomNsk4YS
         z0ezhx7r/Fy529+cMBx/gzQFpM5mDcCf24wJDdwJO33627m7JTciFw+TYLOUMSHaFFQR
         W9HXp9jnkfAHW10LaMUeqqD4pvjzY/zOZHn9GxhFpIaUZ3RrZL90cDdVFbpQ1BD0bJV1
         lMLFhMvjWlmgRsvOhocFrJUvGIssA/XQfu9+VmP/1WQ0PjPK9M4xANw/LzkojuS0WgJR
         6EGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MTg3pn67;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O5j/aAsE+bbxyQPxcHwixZQu4Z5am3/AxfptMqefL7I=;
        b=dQS6blCg1C9HhFcmXBKQsmQhtxhkhzp1cZEp4UB36E3BvVG59YGwvR+4qFVAptYynw
         oiPxfm+XGizYN/ySKwl256p85k8BH5Ju41/YkcbAQf76NoRdBUUIbV5EC+RtmBLe5Lh/
         To4SlqB7qrR6AECYwax0bJHlAHQX7YPEWlA0zK+hsReTMLFt8Em13WDTEWkQhNGEQe4S
         4LSMharHe+yFXZGf1EhZ48yVOMIJ15I2skv08C8wwiwx35xnYRMIeKhLv5lFUgXRqDfO
         JO41lbY4o6o9Bcph55CB2RjWp54FUmoiS5f2bDPVyB89S7SC78TGtlEZti2+Q7T6CsCe
         LLpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O5j/aAsE+bbxyQPxcHwixZQu4Z5am3/AxfptMqefL7I=;
        b=oZVFJWSL6dBo5eEjwrAnlDJ0m0S+qdnvm1YjSJAqGAEp5pUktfDHr2CtzjCuSX0L/g
         bX5i+Zwb2BlrKPl4nmd904Huev++d2VUnLOUJvlta/msONL3SgCsBybRzJA1Q1oRLccj
         rCXUdRS3yJe1bj9ubu+cH7UQc0D8R6oxo1NcvwhWLqjk/0QEhFCLNUw5r0rHxsmFko1E
         c+vjctyjcMPz+Ejnmr8dG3tE3Ayy/8Ec2IYibFsg2k+MLE2o39ctbsUOHMhJSrofvOoV
         TlXAgNyq2kpnM7cLspM2lSO/1mUbtjhzW2CMfiylE4RLjmjrX14XMuDc2W0ltyYS6GpE
         BvDw==
X-Gm-Message-State: APjAAAUKM+9/anbrJRUzeSfIlavabnABDiwR3n1lRy4314dvR0XsghlZ
	7qtmb1mIQFNDRtMBmffnnZ0=
X-Google-Smtp-Source: APXvYqyVatYkPT7+GSOtgxyuXE769epLgnDH+HzXup7NjGxZVhfKX+tnvDOtKQkKQLoXDHmwp5nIyQ==
X-Received: by 2002:ac8:474b:: with SMTP id k11mr7844968qtp.152.1573735340949;
        Thu, 14 Nov 2019 04:42:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9e0e:: with SMTP id h14ls790234qke.7.gmail; Thu, 14 Nov
 2019 04:42:20 -0800 (PST)
X-Received: by 2002:ae9:ea06:: with SMTP id f6mr7501173qkg.246.1573735340602;
        Thu, 14 Nov 2019 04:42:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573735340; cv=none;
        d=google.com; s=arc-20160816;
        b=hfNDk8dyYWU66Enl47TT3bhM/EW8vJkvIHSj1GBs4w0Y+pirnaC8d+S0m/3IAMojNS
         TjxvjsYX4P8iC7BFrvcKCbSm2Ca++BRpaIQmFKgOyLMWlvye5Pl9On/kVTMIjJv4Ma8i
         T0V3V1t248M7PatggsUHw3dde+FUDBompkYn1pz+0cLvlIghIYdVdqvs9V0v+Pq6Zk/a
         JuPnBLOuYLZMdshQvSz+caXsiDTFx4egYVelWm0X9Qf+yg2MZzGwKGHHbtt1KXEBf+oQ
         xcKq9mjDX0kJLNZ6zXiA71MP/PfJ5c0F2XbTDOiV9XIObDi1DEr01179DNFc/LfKZEWb
         sXOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TSvNU69eXGIrS0rn+BnGRZAf/NJLIPfUZKhpOQfyRVI=;
        b=rhTgSa8kvQo9OoY6Ya/y80jvRQbTheTYAydesUne/gPzyC+rpAivth/cf7RyoGbCxf
         sHb5l42L0V78yQRslhS5cbk6MsqU4cmeFBNBMIuBDpRh4fpemvavUBfnTi7ECJuSLosD
         lrVyAFXHonb5Uso4WLAnZHuwdJNCvyvy2X2KjNqfzgDAyC5gubk8RvSPAWP6iLMdf2uP
         q0LQaQNcENPBpsYRWflZUBtS+da21xakxaRkiwwKQe+vfWagVQo4g4UK+yUA8XNRvHOE
         loQYiFLIOhsyZjOPtpcCiSbatvv0ayxgUrMeS4zIHkAeT3n0YNm8YHlp9nXr351r+Ags
         6/DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MTg3pn67;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id a189si295851qkb.4.2019.11.14.04.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 04:42:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id c9so2242458qvz.9
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 04:42:20 -0800 (PST)
X-Received: by 2002:a0c:c125:: with SMTP id f34mr7666929qvh.22.1573735339703;
 Thu, 14 Nov 2019 04:42:19 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
In-Reply-To: <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 13:42:07 +0100
Message-ID: <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Thomas Gleixner <tglx@linutronix.de>
Cc: syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, sboyd@kernel.org, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MTg3pn67;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Thu, 14 Nov 2019, syzbot wrote:
>
> From the full console output:
>
> kasan: CONFIG_KASAN_INLINE enabled
> kasan: GPF could be caused by NULL-ptr deref or user memory access
> general protection fault: 0000 [#1] PREEMPT SMP KASAN
> RIP: 0010:__x64_sys_settimeofday+0x170/0x320
>
> Code: 85 50 ff ff ff 85 c0 0f 85 50 01 00 00 e8 b8 cd 10 00 48 8b 85 48 ff ff ff 48 c1 e8 03 48 89 c2 48 b8 00 00 00 00 00 fc ff df <80> 3c 02 00 0f 85 8a 01 00 00 49 8b 74 24 08 bf 40 42 0f 00 48 89
>
>       80 3c 02 00             cmpb   $0x0,(%rdx,%rax,1)
>
> RSP: 0018:ffff888093d0fe58 EFLAGS: 00010206
> RAX: dffffc0000000000 RBX: 1ffff110127a1fcd RCX: ffffffff8162e915
> RDX: 00000fff820fb94b RSI: ffffffff8162e928 RDI: 0000000000000005
>
> i.e.
>
>      *(0x00000fff820fb94b + 0xdffffc0000000000 * 1) == 0
>
>      *(0xe0000bff820fb94b) == 0
>
> So base == 0x00000fff820fb94b and index == 0xdffffc0000000000 and scale =
> 1. As scale is 1, base and index might be swapped, but that still does not
> make any sense.
>
> 0xdffffc0000000000 is explicitely loaded into RAX according to the
> disassembly, but I can't find the corresponding source as this is in the
> middle of the function prologue and looks KASAN related.
>
> RBP: ffff888093d0ff10 R08: ffff8880a8904380 R09: ffff8880a8904c18
> R10: fffffbfff1390d30 R11: ffffffff89c86987 R12: 00007ffc107dca50
> R13: ffff888093d0fee8 R14: 00007ffc107dca10 R15: 0000000000087a85
> FS:  00007f614c01b700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: 00007f4440cdf000 CR3: 00000000a5236000 CR4: 00000000001406f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>  ? do_sys_settimeofday64+0x250/0x250
>  ? trace_hardirqs_on_thunk+0x1a/0x1c
>  ? do_syscall_64+0x26/0x760
>  ? entry_SYSCALL_64_after_hwframe+0x49/0xbe
>  ? do_syscall_64+0x26/0x760
>  ? lockdep_hardirqs_on+0x421/0x5e0
>  ? trace_hardirqs_on+0x67/0x240
>  do_syscall_64+0xfa/0x760
>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
> The below is the user code which triggered that:
>
> RIP: 0033:0x7f614bb16047
>
> Code: ff ff 73 05 48 83 c4 08 c3 48 8b 0d eb 7d 2e 00 31 d2 48 29 c2 64 89 11 48 83 c8 ff eb e6 90 90 90 90 90 b8 a4 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d c1 7d 2e 00 31 d2 48 29 c2 64
>
>   23:   b8 a4 00 00 00          mov    $0xa4,%eax
>   28:   0f 05                   syscall
>   2a:*  48 3d 01 f0 ff ff       cmp    $0xfffffffffffff001,%rax
>   30:   73 01                   jae    0x33
>   32:   c3                      retq
>
> RSP: 002b:00007ffc107dc978 EFLAGS: 00000206 ORIG_RAX: 00000000000000a4
> RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f614bb16047
> RDX: 000000005dcd1ee0 RSI: 00007ffc107dca10 RDI: 00007ffc107dca50
> RBP: 0000000000000000 R08: 00007ffc107e6080 R09: 0000000000000eca
> R10: 0000000000000000 R11: 0000000000000206 R12: 0000000000000000
> R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
>
> So RAX is obviously the syscall number and the arguments are in RDI (tv()
> and RSI (tz), which both look like legit user space addresses.
>
> As this is deep in the function prologue compiler/KASAN people might want
> to have a look at that.

Looks like a plain user memory access:

SYSCALL_DEFINE2(settimeofday, struct __kernel_old_timeval __user *, tv,
struct timezone __user *, tz)
{
....
if (tv->tv_usec > USEC_PER_SEC)  // <==== HERE
return -EINVAL;

Urgently need +Jann's patch to better explain these things!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g%40mail.gmail.com.
